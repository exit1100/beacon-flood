#include <stdio.h>
#include <stdint.h>

struct radiotap_header {
    uint8_t     version;     /* set to 0 */
    uint8_t     pad;
    uint16_t    len;         /* entire length */
    uint32_t    present;     /* fields present */
    uint8_t     dummy[16];
} __attribute__((__packed__));

struct beacon_header{
    uint16_t frame_control;
    uint16_t duration_id;
    uint8_t dhost[6];  //목적지 주소
    uint8_t shost[6];  //출발지 주소
    uint8_t bssid[6];
    uint16_t squence_control;
} __attribute__ ((__packed__));

struct fixed_parameters{
    uint8_t timestamp[8];
    uint16_t beacon_interval;
    uint16_t capacity_info;
} __attribute__ ((__packed__));

struct tag_SSID_parameter{
    uint8_t element_id;
    uint8_t len;
    char ssid[32];
} __attribute__ ((__packed__));

struct tag_supported_rates{
    uint8_t number;
    uint8_t len;
    uint8_t rates[3];
} __attribute__ ((__packed__));

struct tag_DS_parameter{
    uint8_t number;
    uint8_t len;
    uint8_t channel;
} __attribute__ ((__packed__));

struct fake_beacon{
    struct radiotap_header radiotap;
    struct beacon_header becon;
    struct fixed_parameters fixed;
    struct tag_SSID_parameter tag_ssid;
    //struct tag_supported_rates tag_sup;
    //struct tag_DS_parameter tag_ds;
} __attribute__ ((__packed__));
