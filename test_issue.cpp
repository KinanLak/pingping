#include <iostream>
#include <string>
#include <cstdlib>
#include <thread>
#include <chrono>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <unistd.h>
#include <cstring>
#include <sys/time.h>

// Test program to reproduce the issue described in the GitHub issue
// This will test if the ping_host function correctly identifies responding vs non-responding addresses

class TestPingHost {
private:
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

    // Original ping_host function from the codebase
    bool ping_host_original(const std::string& ip, int timeout_ms = 20) {
        int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
        if (sockfd < 0) {
            // Fallback: utiliser la commande ping système
            std::string cmd = "ping -c 1 -W " + std::to_string(timeout_ms) + " " + ip + " > /dev/null 2>&1";
            return system(cmd.c_str()) == 0;
        }

        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        inet_pton(AF_INET, ip.c_str(), &addr.sin_addr);

        // Préparer le paquet ICMP
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
            // Vérifier si c'est une réponse ICMP valide
            struct ip* ip_hdr = (struct ip*)buffer;
            if (ip_hdr->ip_p == IPPROTO_ICMP) {
                struct icmp* recv_icmp = (struct icmp*)(buffer + (ip_hdr->ip_hl << 2));
                if (recv_icmp->icmp_type == ICMP_ECHOREPLY) {
                    // THIS IS THE BUG: No source IP verification!
                    return true;
                }
            }
        }

        return false;
    }

    // Fixed ping_host function with source IP verification
    bool ping_host_fixed(const std::string& ip, int timeout_ms = 20) {
        int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
        if (sockfd < 0) {
            // Fallback: utiliser la commande ping système
            std::string cmd = "ping -c 1 -W " + std::to_string(timeout_ms) + " " + ip + " > /dev/null 2>&1";
            return system(cmd.c_str()) == 0;
        }

        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        inet_pton(AF_INET, ip.c_str(), &addr.sin_addr);

        // Préparer le paquet ICMP
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
            // Vérifier si c'est une réponse ICMP valide
            struct ip* ip_hdr = (struct ip*)buffer;
            if (ip_hdr->ip_p == IPPROTO_ICMP) {
                struct icmp* recv_icmp = (struct icmp*)(buffer + (ip_hdr->ip_hl << 2));
                if (recv_icmp->icmp_type == ICMP_ECHOREPLY) {
                    // FIX: Verify the source IP matches the target IP
                    if (from.sin_addr.s_addr == addr.sin_addr.s_addr) {
                        return true;
                    }
                }
            }
        }

        return false;
    }

public:
    void test_ping_behavior() {
        std::cout << "Testing ping behavior for false positives..." << std::endl;
        
        // Test with localhost (should respond)
        std::cout << "Testing 127.0.0.1 (should respond):" << std::endl;
        std::cout << "  Original: " << (ping_host_original("127.0.0.1") ? "RESPONDS" : "NO RESPONSE") << std::endl;
        std::cout << "  Fixed: " << (ping_host_fixed("127.0.0.1") ? "RESPONDS" : "NO RESPONSE") << std::endl;
        
        // Test with non-existent localhost address (should not respond)
        std::cout << "Testing 127.0.0.2 (should not respond):" << std::endl;
        std::cout << "  Original: " << (ping_host_original("127.0.0.2") ? "RESPONDS" : "NO RESPONSE") << std::endl;
        std::cout << "  Fixed: " << (ping_host_fixed("127.0.0.2") ? "RESPONDS" : "NO RESPONSE") << std::endl;
        
        // Test with another non-existent address
        std::cout << "Testing 127.0.0.3 (should not respond):" << std::endl;
        std::cout << "  Original: " << (ping_host_original("127.0.0.3") ? "RESPONDS" : "NO RESPONSE") << std::endl;
        std::cout << "  Fixed: " << (ping_host_fixed("127.0.0.3") ? "RESPONDS" : "NO RESPONSE") << std::endl;
    }
};

int main() {
    std::cout << "PingPing Issue Test - False Positives" << std::endl;
    std::cout << "=====================================" << std::endl;
    
    TestPingHost tester;
    tester.test_ping_behavior();
    
    return 0;
}