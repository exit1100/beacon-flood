#ifndef BEACON_H
#define BEACON_H
#include <stdio.h>
#include <stdint.h>

struct MAC_address {
    uint8_t byteMAC[6] = {0x0,};
    uint8_t strMAC[18] = {0x0,};
}

struct radiotap_header {
    uint8_t     version = 0x00;     /* set to 0 */
    uint8_t     pad = 0x00;
    uint16_t    len = 0x0018;         /* entire length */
    uint32_t    present = 0xa000402e;     /* fields present */
    uint8_t     dummy[16] = {0,};
} __attribute__((__packed__));

struct IEEE_802dot11 {
    uint16_t frame_control = 0x0080;
    uint16_t duration_id = 0x0000;
    uint8_t dhost[6] = {0xff,0xff,0xff,0xff,0xff,0xff};  //목적지 주소
    uint8_t shost[6] = {0,};  //출발지 주소
    uint8_t bssid[6] = {0,};
    uint16_t squence_control = 0x0000;
} __attribute__ ((__packed__));


struct fixed_parameters{
    uint64_t timestamp = 0x00;
    uint16_t beacon_interval = 0x0000;
    uint16_t capacity_info = 0x0000;
} __attribute__ ((__packed__));

struct tag_parameter{
    uint8_t element_id = 0x00;
    uint8_t len = 0x00;
} __attribute__ ((__packed__));

struct tag_SSID_parameter{
    uint8_t element_id = 0x00;
    uint8_t len = 32;
    uint8_t ssid[32] = {0,};
} __attribute__ ((__packed__));

struct tag_DS_parameter{
    uint8_t element_id = 0x00;
    uint8_t len = 0x1;
    uint8_t channel = 0x01;
} __attribute__ ((__packed__));

struct tag_support_parameter {
    uint8_t number = 0x01;
    uint8_t length = 0x03;
    uint8_t rates[3] = {0,};
} __attribute__ ((__packed__));

struct beacon_frame{
    struct radiotap_header radiotap;
    struct IEEE_802dot11 beacon;
    struct fixed_parameters fixed;
    struct tag_SSID_parameter tag_ssid;
    struct tag_support_parameter tag_sup;
    struct tag_DS_parameter tag_ds;
} __attribute__ ((__packed__));


char * byte2str_MAC(struct * MAC_address){
    sprintf(MAC_address.strMAC,"%02x:%02x:%02x:%02x:%02x:%02x",MAC_address.byteMAC[0],MAC_address.byteMAC[1],MAC_address.byteMAC[2],MAC_address.byteMAC[3],MAC_address.byteMAC[4],MAC_address.byteMAC[5]);
    return MAC_address.strMAC;
}

#endif // BEACON_H