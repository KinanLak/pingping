#include <iostream>
#include <thread>
#include <vector>
#include <queue>
#include <mutex>
#include <condition_variable>
#include <chrono>
#include <atomic>
#include <sstream>
#include <cstring>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <iomanip>
#include <fstream>
#include <set>

// --- Constantes de configuration pour la compilation ---
#define IP_RANGE_START "14.0.0.0"
#define IP_RANGE_END "14.5.255.255"
#define PING_TIMEOUT_MS 1000
#define PING_THREADS_DEFAULT 96
#define PING_PROGRESS_STEP 16384

#ifdef __APPLE__
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <sys/types.h>
#include <sys/sysctl.h>
#else
#include <netinet/ip_icmp.h>
#include <netinet/ip.h>
#endif

// Structure pour stocker les informations de retry
struct RetryInfo {
    std::string ip;
    int attempt_count;

    RetryInfo(const std::string& ip_addr, int count = 1) : ip(ip_addr), attempt_count(count) {}
};

class PingScanner {
private:
    std::queue<std::string> ip_queue;
    std::queue<RetryInfo> retry_queue;
    std::set<std::string> failed_ips;
    std::mutex queue_mutex;
    std::mutex retry_mutex;
    std::mutex failed_mutex;
    std::condition_variable cv;
    std::atomic<bool> finished{false};
    std::atomic<int> active_responses{0};
    std::atomic<int> processed_count{0};
    int total_ips{0};
    int current_retry_round{0};
    const int max_retries{3};
    std::mutex output_mutex;

    // Calcul du checksum ICMP
    uint16_t checksum(void* b, int len) {
        uint16_t *buf = (uint16_t*)b;
        unsigned int sum = 0;
        uint16_t result;

        while (len > 1) {
            sum += *buf++;
            len -= 2;
        }

        if (len == 1) {
            sum += *(unsigned char*)buf << 8;
        }

        while (sum >> 16) {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }

        result = ~sum;
        return result;
    }

    bool ping_host(const std::string& ip, int timeout_ms = PING_TIMEOUT_MS) {
        int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
        if (sockfd < 0) {
            // Fallback: utiliser la commande ping système (syntaxe macOS)
            int timeout_sec = std::max(1, timeout_ms / 1000);
            std::string cmd = "ping -c 1 -W " + std::to_string(timeout_sec) + " " + ip + " > /dev/null 2>&1";
            bool result = system(cmd.c_str()) == 0;
            if (result) {
                std::lock_guard<std::mutex> lock(output_mutex);
                active_responses++;
            }
            return result;
        }

        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        inet_pton(AF_INET, ip.c_str(), &addr.sin_addr);

        // Préparer le paquet ICMP (structure macOS)
        struct icmp icmp_hdr;
        memset(&icmp_hdr, 0, sizeof(icmp_hdr));
        icmp_hdr.icmp_type = ICMP_ECHO;
        icmp_hdr.icmp_code = 0;
        icmp_hdr.icmp_id = htons(getpid());
        icmp_hdr.icmp_seq = htons(1);
        icmp_hdr.icmp_cksum = 0;
        icmp_hdr.icmp_cksum = checksum(&icmp_hdr, sizeof(icmp_hdr));

        // Configurer le timeout
        struct timeval tv;
        tv.tv_sec = timeout_ms / 1000;
        tv.tv_usec = (timeout_ms % 1000) * 1000;
        setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

        // Envoyer le ping
        auto start = std::chrono::high_resolution_clock::now();
        int result = sendto(sockfd, &icmp_hdr, sizeof(icmp_hdr), 0,
                          (struct sockaddr*)&addr, sizeof(addr));

        if (result < 0) {
            close(sockfd);
            return false;
        }

        // Attendre la réponse
        char buffer[1024];
        struct sockaddr_in from;
        socklen_t from_len = sizeof(from);

        result = recvfrom(sockfd, buffer, sizeof(buffer), 0,
                         (struct sockaddr*)&from, &from_len);

        close(sockfd);

        if (result > 0) {
            auto end = std::chrono::high_resolution_clock::now();
            auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);

            // Vérifier si c'est une réponse ICMP valide
            struct ip* ip_hdr = (struct ip*)buffer;
            if (ip_hdr->ip_p == IPPROTO_ICMP) {
                struct icmp* recv_icmp = (struct icmp*)(buffer + (ip_hdr->ip_hl << 2));
                if (recv_icmp->icmp_type == ICMP_ECHOREPLY) {
                    // Vérifier que la réponse provient bien de l'IP cible
                    if (from.sin_addr.s_addr == addr.sin_addr.s_addr) {
                        std::lock_guard<std::mutex> lock(output_mutex);
                        //std::cout << "✓ " << ip << " - " << duration.count() << "ms" << std::endl;
                        active_responses++;
                        return true;
                    }
                }
            }
        }

        return false;
    }

    void worker_thread() {
        while (true) {
            std::unique_lock<std::mutex> lock(queue_mutex);
            cv.wait(lock, [this] { return !ip_queue.empty() || finished; });

            if (finished && ip_queue.empty()) {
                break;
            }

            std::string ip = ip_queue.front();
            ip_queue.pop();
            lock.unlock();

            // Ping l'adresse
            if (!ping_host(ip)) {
                // Ajouter à la queue de retry si on n'a pas encore atteint le max
                std::lock_guard<std::mutex> retry_lock(retry_mutex);
                retry_queue.push(RetryInfo(ip, 1));
            }

            // Incrémenter le compteur et afficher la progression
            int current_count = ++processed_count;
            if (current_count % PING_PROGRESS_STEP == 0) {
                std::lock_guard<std::mutex> out_lock(output_mutex);
                double progress = (double)current_count / total_ips * 100.0;
                std::cout << "[PROGRESSION] " << current_count << "/" << total_ips
                          << " (" << std::fixed << std::setprecision(1) << progress
                          << "%) - Réponses actives: " << active_responses << std::endl;
            }
        }
    }

    void retry_worker_thread() {
        while (true) {
            std::unique_lock<std::mutex> lock(retry_mutex);
            cv.wait(lock, [this] { return !retry_queue.empty() || finished; });

            if (finished && retry_queue.empty()) {
                break;
            }

            RetryInfo retry_info = retry_queue.front();
            retry_queue.pop();
            lock.unlock();

            // Tenter de pinger à nouveau
            if (!ping_host(retry_info.ip)) {
                if (retry_info.attempt_count < max_retries) {
                    // Ajouter à nouveau dans la queue avec un compteur incrémenté
                    std::lock_guard<std::mutex> retry_lock(retry_mutex);
                    retry_queue.push(RetryInfo(retry_info.ip, retry_info.attempt_count + 1));
                } else {
                    // Max de tentatives atteint, ajouter aux IP qui ont échoué
                    std::lock_guard<std::mutex> failed_lock(failed_mutex);
                    failed_ips.insert(retry_info.ip);
                }
            }

            // Incrémenter le compteur de progression pour les retries aussi
            int current_count = ++processed_count;
            if (current_count % PING_PROGRESS_STEP == 0) {
                std::lock_guard<std::mutex> out_lock(output_mutex);
                std::cout << "[RETRY PROGRESSION] Tentative " << retry_info.attempt_count
                          << " pour " << retry_info.ip << " - Réponses actives: " << active_responses << std::endl;
            }
        }
    }

    void write_failed_ips_to_file() {
        std::ofstream file("failed_ips.txt");
        if (file.is_open()) {
            std::lock_guard<std::mutex> failed_lock(failed_mutex);
            for (const auto& ip : failed_ips) {
                file << ip << std::endl;
            }
            file.close();
            std::cout << "Les IP qui ont échoué ont été écrites dans 'failed_ips.txt' ("
                      << failed_ips.size() << " adresses)" << std::endl;
        } else {
            std::cerr << "Erreur: Impossible d'ouvrir le fichier 'failed_ips.txt' pour écriture" << std::endl;
        }
    }

    // Fonctions utilitaires pour gérer les plages d'IP
    std::vector<int> parse_ip(const std::string& ip) {
        std::vector<int> parts;
        std::stringstream ss(ip);
        std::string part;

        while (std::getline(ss, part, '.')) {
            parts.push_back(std::stoi(part));
        }

        if (parts.size() != 4) {
            throw std::invalid_argument("Format IP invalide: " + ip);
        }

        for (int part : parts) {
            if (part < 0 || part > 255) {
                throw std::invalid_argument("Octet IP invalide: " + std::to_string(part));
            }
        }

        return parts;
    }

    uint32_t ip_to_uint32(const std::vector<int>& ip_parts) {
        return (ip_parts[0] << 24) | (ip_parts[1] << 16) | (ip_parts[2] << 8) | ip_parts[3];
    }

    std::string uint32_to_ip(uint32_t ip) {
        std::stringstream ss;
        ss << ((ip >> 24) & 0xFF) << "."
           << ((ip >> 16) & 0xFF) << "."
           << ((ip >> 8) & 0xFF) << "."
           << (ip & 0xFF);
        return ss.str();
    }

    void generate_ip_range(const std::string& start_ip, const std::string& end_ip) {
        try {
            std::vector<int> start_parts = parse_ip(start_ip);
            std::vector<int> end_parts = parse_ip(end_ip);

            uint32_t start_uint = ip_to_uint32(start_parts);
            uint32_t end_uint = ip_to_uint32(end_parts);

            if (start_uint > end_uint) {
                throw std::invalid_argument("L'IP de début doit être inférieure ou égale à l'IP de fin");
            }

            std::lock_guard<std::mutex> lock(queue_mutex);
            for (uint32_t ip = start_uint; ip <= end_uint; ip++) {
                ip_queue.push(uint32_to_ip(ip));
            }

        } catch (const std::exception& e) {
            throw std::runtime_error("Erreur lors de la génération de la plage IP: " + std::string(e.what()));
        }
    }

public:
    void scan_range(const std::string& start_ip, const std::string& end_ip, int num_threads = std::thread::hardware_concurrency()) {
        std::cout << "Démarrage du scan des adresses de " << start_ip << " à " << end_ip << " avec "
                  << num_threads << " threads..." << std::endl;
        std::cout << "Note: Exécutez avec sudo pour utiliser les raw sockets (plus rapide)" << std::endl;
        std::cout << "      Sur macOS, les raw sockets nécessitent des privilèges root" << std::endl;
        std::cout << "Sinon, le programme utilisera la commande ping système" << std::endl;
        std::cout << "Maximum de " << max_retries << " tentatives par IP" << std::endl << std::endl;

        // Générer la plage d'adresses IP
        try {
            generate_ip_range(start_ip, end_ip);
        } catch (const std::exception& e) {
            std::cerr << "Erreur: " << e.what() << std::endl;
            return;
        }

        total_ips = ip_queue.size();
        std::cout << "Addresses à tester: " << total_ips << std::endl << std::endl;

        auto start_time = std::chrono::high_resolution_clock::now();

        // Phase 1: Scan initial
        std::cout << "=== PHASE 1: SCAN INITIAL ===" << std::endl;
        run_ping_phase(num_threads, false);

        // Phases de retry
        for (int retry_round = 1; retry_round <= max_retries; retry_round++) {
            std::lock_guard<std::mutex> retry_lock(retry_mutex);
            if (retry_queue.empty()) {
                break;
            }

            std::cout << "=== PHASE " << (retry_round + 1) << ": RETRY " << retry_round << " ===" << std::endl;
            std::cout << "IP à retenter: " << retry_queue.size() << std::endl;

            // Relâcher le lock pour permettre le traitement
            retry_lock.~lock_guard();

            run_ping_phase(num_threads, true);
        }

        auto end_time = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::seconds>(end_time - start_time);

        std::cout << std::endl << "=== RÉSULTATS FINAUX ===" << std::endl;
        std::cout << "Scan terminé en " << duration.count() << " secondes" << std::endl;
        std::cout << "Adresses testées: " << total_ips << std::endl;
        std::cout << "Adresses qui répondent: " << active_responses << std::endl;
        std::cout << "Adresses qui ont échoué (après " << max_retries << " tentatives): " << failed_ips.size() << std::endl;
        std::cout << "Threads: " << num_threads << std::endl;

        // Écrire les IP qui ont échoué dans un fichier
        write_failed_ips_to_file();
    }

private:
    void run_ping_phase(int num_threads, bool is_retry_phase) {
        finished = false;

        // Démarrer les threads de travail
        std::vector<std::thread> threads;

        for (int i = 0; i < num_threads; i++) {
            if (is_retry_phase) {
                threads.emplace_back(&PingScanner::retry_worker_thread, this);
            } else {
                threads.emplace_back(&PingScanner::worker_thread, this);
            }
        }

        // Attendre que toutes les queues soient vides
        bool all_empty = false;
        while (!all_empty) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));

            std::lock_guard<std::mutex> queue_lock(queue_mutex);
            std::lock_guard<std::mutex> retry_lock(retry_mutex);

            if (is_retry_phase) {
                all_empty = retry_queue.empty();
            } else {
                all_empty = ip_queue.empty();
            }
        }

        // Marquer comme terminé et réveiller tous les threads
        {
            std::lock_guard<std::mutex> lock(queue_mutex);
            finished = true;
        }
        cv.notify_all();

        for (auto& thread : threads) {
            thread.join();
        }
    }
};

int main(int argc, char* argv[]) {
    int num_threads = PING_THREADS_DEFAULT;
    std::string start_ip = IP_RANGE_START;  // IP par défaut
    std::string end_ip = IP_RANGE_END;  // IP par défaut

    if (argc < 3) {
        std::cout << "Utilisation: " << argv[0] << " <IP_debut> <IP_fin> [nombre_threads]" << std::endl;
        std::cout << "Exemple: " << argv[0] << " 192.168.1.1 192.168.1.254 64" << std::endl;
        std::cout << "Utilisation des valeurs par défaut: " << start_ip << " à " << end_ip << std::endl;
    } else {
        start_ip = argv[1];
        end_ip = argv[2];

        if (argc > 3) {
            num_threads = std::stoi(argv[3]);
            if (num_threads < 1 || num_threads > 1000) {
                std::cerr << "Nombre de threads invalide (1-1000). Utilisation: " << argv[0] << " <IP_debut> <IP_fin> [nombre_threads]" << std::endl;
                return 1;
            }
        }
    }

    std::cout << "=== PING SCANNER PARALLÉLISÉ ===" << std::endl;
    std::cout << "Plage IP: " << start_ip << " - " << end_ip << std::endl;
    std::cout << "Threads: " << num_threads << std::endl;

    PingScanner scanner;
    scanner.scan_range(start_ip, end_ip, num_threads);

    return 0;
}
