#include <iostream>
#include <string>
#include <vector>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <unistd.h>
#include <cstring>
#include <sys/time.h>
#include <cstdlib>

class PingFixTest {
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

    // Fixed ping_host function with source IP verification
    bool ping_host_fixed(const std::string& ip, int timeout_ms = 1000) {
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
    void test_comprehensive() {
        std::cout << "Comprehensive test of ping fix..." << std::endl;
        
        std::vector<std::string> test_ips = {
            "127.0.0.1",     // Should respond
            "127.0.0.2",     // Should not respond
            "127.0.0.3",     // Should not respond
            "127.0.0.4",     // Should not respond
            "127.0.0.5",     // Should not respond
            "169.254.1.1",   // Should not respond (link-local)
            "169.254.1.2",   // Should not respond (link-local)
            "10.0.0.1",      // Should not respond (private)
            "10.0.0.2",      // Should not respond (private)
            "192.168.1.1"    // Should not respond (private)
        };

        for (const auto& ip : test_ips) {
            std::cout << "Testing " << ip << ": ";
            
            // Test system ping first
            std::string cmd = "ping -c 1 -W 1000 " + ip + " > /dev/null 2>&1";
            bool system_ping_result = system(cmd.c_str()) == 0;
            
            // Test our fixed function
            bool fixed_result = ping_host_fixed(ip);
            
            std::cout << "System ping: " << (system_ping_result ? "RESPONDS" : "NO RESPONSE");
            std::cout << ", Fixed ping: " << (fixed_result ? "RESPONDS" : "NO RESPONSE");
            
            if (system_ping_result == fixed_result) {
                std::cout << " ✓ MATCH" << std::endl;
            } else {
                std::cout << " ✗ MISMATCH" << std::endl;
            }
        }
    }
};

int main() {
    std::cout << "PingPing Fix Validation Test" << std::endl;
    std::cout << "============================" << std::endl;
    
    PingFixTest tester;
    tester.test_comprehensive();
    
    return 0;
}