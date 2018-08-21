//
// Created by CyberDriver on 2018/8/20.
//

#include "tcp_rst.h"

void err_quit(const char *msg){
    perror(msg);
    exit(1);
}


libnet_t *Libnet_init(int injection_type, const char *device, char *err_buf){
    libnet_t *ret;
    if ((ret = libnet_init(injection_type, device, err_buf)) == NULL)
        err_quit(err_buf);
    return ret;
}

uint32_t
Libnet_name2addr4(libnet_t *l, char *host_name, uint8_t use_name){
    uint32_t ret;
    if ((ret = libnet_name2addr4(l, host_name, use_name)) == -1)
        err_quit("libnet_name2addr4");
    return ret;
}

libnet_ptag_t
Libnet_build_tcp(uint16_t sp, uint16_t dp, uint32_t seq, uint32_t ack,
                 uint8_t control, uint16_t win, uint16_t sum, uint16_t urg, uint16_t len,
                 const uint8_t* payload, uint32_t payload_s, libnet_t *l, libnet_ptag_t ptag){
    libnet_ptag_t ret;
    if ((ret = libnet_build_tcp(sp, dp, seq, ack, control, win, sum, urg, len, payload, payload_s, l, ptag)) < 0)
        err_quit("libnet_build_tcp error");
    return ret;


}

void Libnet_destroy(libnet_t *l){
    libnet_destroy(l);
}

