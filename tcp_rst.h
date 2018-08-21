//
// Created by CyberDriver on 2018/8/20.
//

#ifndef EXPERT_TCP_RST_H
#define EXPERT_TCP_RST_H

#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <net/ethernet.h>
#include <string.h>
#include <unistd.h>
#include <pcap.h>
#include <libnet.h>


void err_quit(const char *msg);


libnet_t *Libnet_init(int injection_type, const char *device, char *err_buf);

void Libnet_destroy(libnet_t *l);

uint32_t
Libnet_name2addr4(libnet_t *l, char *host_name, uint8_t use_name);

/**
 * Builds an RFC 793 Transmission Control Protocol (TCP) header.
 * @param sp source port
 * @param dp destination port
 * @param seq sequence number
 * @param ack acknowledgement number
 * @param control control flags
 * @param win window size
 * @param sum checksum (0 for libnet to autofill)
 * @param urg urgent pointer
 * @param len total length of the TCP packet (for checksum calculation)
 * @param payload
 * @param payload_s payload length or 0
 * @param l pointer to a libnet context
 * @param ptag protocol tag to modify an existing header, 0 to build a new one
 * @return protocol tag value on success
 * @retval -1 on error
 */
libnet_ptag_t
Libnet_build_tcp(uint16_t sp, uint16_t dp, uint32_t seq, uint32_t ack,
                 uint8_t control, uint16_t win, uint16_t sum, uint16_t urg, uint16_t len,
                 const uint8_t* payload, uint32_t payload_s, libnet_t *l, libnet_ptag_t ptag);

#endif //EXPERT_TCP_RST_H
