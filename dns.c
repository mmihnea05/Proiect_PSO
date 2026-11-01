#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#define PORT 53
#define BUF_SIZE 512 // pachetele DNS standard UDP au maxim 512 bytes

// structura header DNS (12 bytes)
// obligam compilatorul sa nu adauge spatii goale in memorie
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

// transformam formatul DNS intr-un string normal: [3]www[6]google[3]com[0] -> www.google.com
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
    
    // eliminam ultimul punct adaugat si punem terminator de sir
    if (p > 0) {
        output[p - 1] = '\0';
    } else {
        output[0] = '\0';
    }
}

int main() {
    int sockfd;
    struct sockaddr_in server_addr, client_addr;
    unsigned char buffer[BUF_SIZE];
    socklen_t client_len = sizeof(client_addr);

    // creare socket UDP
    if ((sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
        perror("Eroare la crearea socket-ului");
        exit(EXIT_FAILURE);
    }

    // config adresa server
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY; // ascultam pe toate interfetele de retea
    server_addr.sin_port = htons(PORT);       // portul standard UDP : 53

    // legam socketul de port
    if (bind(sockfd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("Eroare la bind. Sudo?");
        exit(EXIT_FAILURE);
    }

    printf("Server DNS asculta pe portul %d...\n", PORT);

    // bucla infinita, asteptam clientii
    while (1) {
        // recvfrom blocheaza executia pana primim un pachet
        int received_bytes = recvfrom(sockfd, buffer, BUF_SIZE, 0, 
                                     (struct sockaddr*)&client_addr, &client_len);
        
        // in caz de eroare, trecem la urmat pachet
        if (received_bytes < 0) {
            continue;
        }

        // extragem ip-ul daca pachetul e valid
        char client_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(client_addr.sin_addr), client_ip, INET_ADDRSTRLEN);

        // numele domeniului cerut incepe fix dupa headerul DNS (care are 12 bytes)
        unsigned char *qname = buffer + sizeof(struct DNS_HEADER);
        
        // decodare nume
        char domain_str[256];
        printf("%s\n", qname);
        decode_domain_name(qname, domain_str);

        // afisare rezultat
        printf("Am primit o cerere de la %s pentru domeniul: %s\n", client_ip, domain_str);
    }

    close(sockfd);
    return 0;
}