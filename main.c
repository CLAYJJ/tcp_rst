#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <memory.h>
#include "tcp_rst.h"
void usage(char *name);
/**
 * 使用libnet库构造TCP的RST包
 * @param argc
 * @param argv
 * @return
 */
int main (int argc, char **argv){
    char errbuf[LIBNET_ERRBUF_SIZE];
    libnet_t *l;
    libnet_ptag_t t;
    char *src_ip_str;
    char *dest_ip_str;
    uint32_t src_ip, dest_ip;
    int c, n;
    uint16_t sp, dp;
    char *cp;
    // 解析命令行参数
    while ((c = getopt(argc, argv, "d:s:")) != EOF){
        switch (c) {
            case 'd':
                if ((cp = strrchr(optarg, ':')) == NULL)
                    usage(argv[0]);
                *cp++ = 0;
                dest_ip_str = optarg;
                dp = (uint16_t)atoi(cp);
                break;
            case 's':
                if ((cp = strrchr(optarg, ':')) == NULL)
                    usage(argv[0]);
                *cp++ = 0;
                src_ip_str = optarg;
                sp = (uint16_t)atoi(cp);
                break;
            default:
                usage(argv[0]);
        }
    }

    l = Libnet_init(LIBNET_RAW4, NULL, errbuf);
    src_ip = Libnet_name2addr4(l, src_ip_str, LIBNET_RESOLVE);
    dest_ip = Libnet_name2addr4(l, dest_ip_str, LIBNET_RESOLVE);
    t = libnet_build_tcp_options(
            (uint8_t*)"\003\003\012\001\002\004\001\011\010\012\077\077\077\077\000\000\000\000\000\000",
            20,
            l,
            0);
    if (t == -1) {
        fprintf(stderr, "Can't build TCP options: %s\n", libnet_geterror(l));
        goto bad;
    }
    t = libnet_build_tcp(sp, dp, 0, 0, TH_RST, 0, 0, 0, LIBNET_TCP_H, NULL, 0, l, 0);
    if (t == -1) {
        fprintf(stderr, "Can't build TCP header: %s\n", libnet_geterror(l));
        goto bad;
    }
    t = libnet_build_ipv4(
            LIBNET_IPV4_H + LIBNET_TCP_H + 20,/* length */
            0,                                          /* TOS */
            242,                                        /* IP ID */
            0,                                          /* IP Frag */
            64,                                         /* TTL */
            IPPROTO_TCP,                                /* protocol */
            0,                                          /* checksum */
            src_ip,                                     /* source IP */
            dest_ip,                                     /* destination IP */
            NULL,                                       /* payload */
            0,                                          /* payload size */
            l,                                          /* libnet handle */
            0);
    if (t == -1) {
        fprintf(stderr, "Can't build IP header: %s\n", libnet_geterror(l));
        goto bad;
    }
    /*t = libnet_build_ethernet(
            enet_dst,                                   *//* ethernet destination *//*
            enet_src,                                   *//* ethernet source *//*
            ETHERTYPE_IP,                               *//* protocol type *//*
            NULL,                                       *//* payload *//*
            0,                                          *//* payload size *//*
            l,                                          *//* libnet handle *//*
            0);
    if (t == -1) {
        fprintf(stderr, "Can't build ethernet header: %s\n", libnet_geterror(l));
        goto bad;
    }*/
    n = libnet_write(l);
    if (n == -1) {
        fprintf(stderr, "Write error: %s\n", libnet_geterror(l));
        goto bad;
    } else {
        fprintf(stderr, "Wrote %d byte TCP packet; check the wire.\n", n);
    }
    bad: libnet_destroy(l);
    return 0;
}

void
usage(char *name)
{
    fprintf(stderr,
            "usage: %s -s source_ip.source_port -d destination_ip.destination_port\n",
            name);
    exit(1);
}
