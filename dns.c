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

int main() {
    int sockfd;
    struct sockaddr_in server_addr, client_addr, forward_addr;
    unsigned char buffer[BUF_SIZE];
    
    // creare socket principal
    if ((sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
        perror("Eroare la crearea socket-ului");
        exit(EXIT_FAILURE);
    }

    // configurare adresa server local
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY; 
    server_addr.sin_port = htons(PORT);       

    // legam socketul de port
    if (bind(sockfd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("Eroare la bind. Ai rulat cu sudo?");
        exit(EXIT_FAILURE);
    }

    // configuram adresa serverului extern
    memset(&forward_addr, 0, sizeof(forward_addr));
    forward_addr.sin_family = AF_INET;
    forward_addr.sin_port = htons(PORT); 
    inet_pton(AF_INET, EXTERNAL_DNS, &forward_addr.sin_addr);

    write_log("Server DNS pornit si asculta pe portul %d...\n", PORT);

    // bucla infinita, asteptam clientii
    while (1) {
        
        // primim cererea de la client pe socketul principal
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

        // ignoram cererile inverse
        if (strstr(domain_str, "arpa") != NULL) continue;

        unsigned char *qtype_ptr = qname + strlen((char*)qname) + 1;
        unsigned short qtype = ntohs(*(unsigned short*)qtype_ptr);
        write_log("Cerere [ID: %d] de la %s -> Domeniu: %s (QTYPE: %u)\n", req_id, client_ip, domain_str, qtype);


        // creare socket pt comunicarea cu exteriorul
        int ext_sock;
        if ((ext_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
            write_log("Eroare creare socket extern pentru [ID: %d]\n", req_id);
            continue;
        }

        // setare timeout 3 sec
        struct timeval tv;
        tv.tv_sec = 3;
        tv.tv_usec = 0;
        setsockopt(ext_sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));


        // trimite cererea catre serverul DNS
        printf("forward catre %s...\n", EXTERNAL_DNS);
        sendto(ext_sock, buffer, client_bytes, 0, 
              (struct sockaddr*)&forward_addr, sizeof(forward_addr));


        // asteptam raspunsul
        struct sockaddr_in reply_addr;
        socklen_t reply_len = sizeof(reply_addr);
        int forward_bytes = recvfrom(ext_sock, buffer, BUF_SIZE, 0, 
                                    (struct sockaddr*)&reply_addr, &reply_len);

        if (forward_bytes > 0) {
            write_log("Primit raspuns extern pentru [ID: %d] (%d bytes). Trimis inapoi la client.\n", req_id, forward_bytes);

            // trimitem raspunsul inapoi la client prin socketu-ul principal
            sendto(sockfd, buffer, forward_bytes, 0, 
                  (struct sockaddr*)&client_addr, client_len);
            
            printf("raspuns expediat inapoi catre client\n");
        } else {
            write_log("Timeout (3s): Serverul extern nu a raspuns pentru [ID: %d] (%s)\n", req_id, domain_str);
        }

        // inchidem socket-ul temporar pentru a elibera resursele
        close(ext_sock);
    }

    close(sockfd);
    return 0;
}