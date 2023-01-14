#ifndef BEACON_H
#define BEACON_H
#include <stdio.h>
#include <stdint.h>

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

//int radiotap_length(struct radiotap_header *radiotap_header);
//int beacon_header_length(struct beacon_header *802dot11_header);
//int tag_parameter_number(struct tag_parameter *tag_parameter);
//int tag_parameter_length(struct tag_parameter *tag_parameter);
//int SSID_parameter(struct tag_SSID_parameter *tag_SSID_parameter);
//int DS_parameter(struct tag_DS_parameter *tag_DS_parameter);

#endif // BEACON_H





