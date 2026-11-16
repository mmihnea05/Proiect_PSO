#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <stdarg.h>

#define PORT 53
#define BUF_SIZE 65536 
#define EXTERNAL_DNS "8.8.8.8" 
#define LOG_FILE "dns_server.log"
#define CONFIG_FILE "dnsconfig.txt"

// structura header DNS (12 bytes)
#pragma pack(push, 1)
struct DNS_HEADER {
    unsigned short id;         // id cerere (2 bytes)
    unsigned short flags;      // flaguri (2 bytes)
    unsigned short q_count;    // nr intrebari (2 bytes)
    unsigned short ans_count;  // nr raspunsuri (2 bytes)
    unsigned short auth_count; // nr inreg autoritate (2 bytes)
    unsigned short add_count;  // nr inreg aditionale (2 bytes)
};
#pragma pack(pop)

// transformam formatul DNS intr-un string normal
void decode_domain_name(unsigned char* reader, char* output) {
    int p = 0;
    while (*reader != 0) {
        int len = *reader; 
        reader++;          
        for (int i = 0; i < len; i++) {
            output[p++] = *reader++; 
        }
        output[p++] = '.'; 
    }
    if (p > 0) output[p - 1] = '\0';
    else output[0] = '\0';
}

void write_log(const char *format, ...) {
    va_list args;
    
    time_t now = time(NULL);
    char time_str[20];
    strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", localtime(&now));

    printf("[%s] ", time_str);
    
    va_start(args, format);
    vprintf(format, args);
    va_end(args);
    
    FILE *f = fopen(LOG_FILE, "a");
    if (f != NULL) {
        fprintf(f, "[%s] ", time_str);
        va_start(args, format);
        vfprintf(f, format, args);
        va_end(args);
        fclose(f);
    }
}

// cautam domeniul in fisierul local
int get_ip_from_file(const char *domain, char *ip_buffer) {
    FILE *fp = fopen(CONFIG_FILE, "r");
    if (!fp) return 0;

    char file_domain[256], file_ip[256];
    while (fscanf(fp, "%255s %255s", file_domain, file_ip) == 2) {
        if (strcmp(domain, file_domain) == 0) {
            strcpy(ip_buffer, file_ip);
            fclose(fp);
            return 1;
        }
    }
    fclose(fp);
    return 0;
}

// construim pachetul DNS de raspuns cu IP local
int build_local_response(unsigned char *buffer, int query_len, const char *ip_str) {
    struct DNS_HEADER *dns = (struct DNS_HEADER *)buffer;
    
    // Setam flagurile: response (0x8000) + standard query (0x0000) + no error (0x0000) -> 0x8180
    dns->flags = htons(0x8180);
    dns->ans_count = htons(1); // un singur raspuns

    unsigned char *ans = buffer + query_len;

    // pointer catre nume (compresie DNS 0xC00C)
    *ans++ = 0xC0; *ans++ = 0x0C;
    // type A (1)
    *ans++ = 0x00; *ans++ = 0x01;
    // class IN (1)
    *ans++ = 0x00; *ans++ = 0x01;
    // TTL 300
    *ans++ = 0x00; *ans++ = 0x00; *ans++ = 0x01; *ans++ = 0x2C;
    // data length (4 bytes pt IPv4)
    *ans++ = 0x00; *ans++ = 0x04;

    struct in_addr ip_addr;
    inet_pton(AF_INET, ip_str, &ip_addr);
    memcpy(ans, &ip_addr.s_addr, 4);
    ans += 4;

    return (ans - buffer);
}

void extract_and_cache_ip(unsigned char *buffer, const char *domain) {
    struct DNS_HEADER *dns = (struct DNS_HEADER *)buffer;
    
    // verificam daca avem macar un raspuns
    if (ntohs(dns->ans_count) == 0) return;

    // sarim peste Header (12 bytes)
    unsigned char *reader = buffer + sizeof(struct DNS_HEADER);

    // sarim peste sectiunea question (citim pana dam de byte ul 0)
    while (*reader != 0) reader++;
    reader += 5; // sarim peste byte-ul 0 si peste QTYPE (2 bytes) si QCLASS (2 bytes)

    // acum suntem la inceputul sectiunii ANSWER
    // parcurgem toate raspunsurile oferite
    int stop = 0;
    for (int i = 0; i < ntohs(dns->ans_count); i++) {
        // numele raspunsului e de obicei un pointer
        if (*reader >= 192) {
            reader += 2; // E pointer (2 bytes)
        } else {
            while (*reader != 0) reader++;
            reader += 1;
        }

        // citim tipul inregistrarii (vrem Type 1 = adresa IPv4)
        unsigned short type = ntohs(*(unsigned short*)reader);
        reader += 2; // sarim CLASS (2 bytes)
        reader += 2; // sarim TTL (4 bytes)
        reader += 4;
        
        unsigned short data_len = ntohs(*(unsigned short*)reader);
        reader += 2;

        if (type == 1 && data_len == 4) { // daca este adresa IPv4 valida
            struct in_addr ip_addr;
            memcpy(&ip_addr.s_addr, reader, 4); // copiem cei 4 bytes ai IP-ului
            
            char ip_str[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &ip_addr, ip_str, INET_ADDRSTRLEN);
            
            FILE *fp = fopen(CONFIG_FILE, "a");
            if (fp != NULL) {
                fprintf(fp, "%s %s\n", domain, ip_str);
                fclose(fp);
                write_log("Salvata adresa noua in cache: %s -> %s\n", domain, ip_str);
            }
            
            // dupa ce am salvat prima adresa IPv4 utila ne oprim
            break;
        }

        reader += data_len;
    }
}

int main() {
    int sockfd;
    struct sockaddr_in server_addr, client_addr, forward_addr;
    unsigned char buffer[BUF_SIZE];
    
    if ((sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
        perror("Eroare la crearea socket-ului");
        exit(EXIT_FAILURE);
    }

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY; 
    server_addr.sin_port = htons(PORT);       

    if (bind(sockfd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("Eroare la bind. Ai rulat cu sudo?");
        exit(EXIT_FAILURE);
    }

    memset(&forward_addr, 0, sizeof(forward_addr));
    forward_addr.sin_family = AF_INET;
    forward_addr.sin_port = htons(PORT); 
    inet_pton(AF_INET, EXTERNAL_DNS, &forward_addr.sin_addr);

    write_log("Server DNS pornit si asculta pe portul %d...\n", PORT);

    while (1) {
        socklen_t client_len = sizeof(client_addr);
        int client_bytes = recvfrom(sockfd, buffer, BUF_SIZE, 0, 
                                     (struct sockaddr*)&client_addr, &client_len);
        
        if (client_bytes < 0) continue;

        char client_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(client_addr.sin_addr), client_ip, INET_ADDRSTRLEN);
        
        struct DNS_HEADER *dns = (struct DNS_HEADER*)buffer;
        unsigned short req_id = ntohs(dns->id);

        unsigned char *qname = buffer + sizeof(struct DNS_HEADER);
        char domain_str[256];
        decode_domain_name(qname, domain_str);

        if (strstr(domain_str, "arpa") != NULL) continue;

        unsigned char *qtype_ptr = qname + strlen((char*)qname) + 1;
        unsigned short qtype = ntohs(*(unsigned short*)qtype_ptr);
        write_log("Cerere [ID: %d] de la %s -> Domeniu: %s (QTYPE: %u)\n", req_id, client_ip, domain_str, qtype);

        char found_ip[INET_ADDRSTRLEN];
        
        if (get_ip_from_file(domain_str, found_ip)) {
            write_log("Interceptat [ID: %d]! Rezolvam LOCAL in IP: %s\n", req_id, found_ip);
            
            int response_len = build_local_response(buffer, client_bytes, found_ip);
            
            sendto(sockfd, buffer, response_len, 0, (struct sockaddr*)&client_addr, client_len);
            write_log("Raspuns LOCAL expediat catre client pentru [ID: %d]\n", req_id);
            
        } else {
            write_log("Nu este in fisier. Forward catre %s pentru [ID: %d]\n", EXTERNAL_DNS, req_id);
            
            int ext_sock;
            if ((ext_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
                write_log("Eroare creare socket extern pentru [ID: %d]\n", req_id);
                continue;
            }

            struct timeval tv;
            tv.tv_sec = 3; tv.tv_usec = 0;
            setsockopt(ext_sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

            sendto(ext_sock, buffer, client_bytes, 0, 
                  (struct sockaddr*)&forward_addr, sizeof(forward_addr));

            struct sockaddr_in reply_addr;
            socklen_t reply_len = sizeof(reply_addr);
            int forward_bytes = recvfrom(ext_sock, buffer, BUF_SIZE, 0, 
                                        (struct sockaddr*)&reply_addr, &reply_len);

            if (forward_bytes > 0) {
                write_log("Primit raspuns extern pentru [ID: %d] (%d bytes). Trimis inapoi la client.\n", req_id, forward_bytes);

                sendto(sockfd, buffer, forward_bytes, 0, 
                      (struct sockaddr*)&client_addr, client_len);

                if (qtype == 1) {
                    extract_and_cache_ip(buffer, domain_str);
                }
            } else {
                write_log("Timeout (3s): Serverul extern nu a raspuns pentru [ID: %d] (%s)\n", req_id, domain_str);
            }

            close(ext_sock);
        }
    }

    close(sockfd);
    return 0;
}