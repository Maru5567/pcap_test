#include <pcap.h>
#include <stdio.h>
static int Z = 0;
void print_type(const u_char *ty){
    if((ty[0]<<8|ty[1])==0x0800)
    {
        printf("IPv4\n");
        Z=1;
    }
    else
    {
        printf("other type\n");
        Z=2;
    }
}
void print_mac(const u_char * mac ) {


    printf("%02x:%02x:%02x:%02x:%02x:%02x\n", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}
void ipcheck(const u_char *tt){

    if(tt[0]==0x06){
        printf("TCP \n");
    }
    else{
        printf("other protocol \n");
    }

}
void print_ip(const u_char * ip) {
    printf("%d.%d.%d.%d\n", ip[0], ip[1], ip[2], ip[3]);
}
int start_tcp(const u_char *st){
    return st[0] & 0x0F;
}
int start_http(const u_char *sh){
    return (sh[0]& 0xF0)>>4;
}
void print_port(const u_char * port) {
    printf("%d \n", (port[0] << 8) | port[1]);
}
void print_Tcpdata(const u_char *dd,int lenn){
    if (lenn==0) {
        printf("TCP data size 0 \n");
    }
    else{
        if(lenn<10){
            for(int i=0 ; i<lenn;i++){
                printf("%02x",dd[i]);
            }
        }
        else{
        for(int i =0 ; i<10 ;i++){

            printf("%02x",dd[i]);
        }
            }
        printf("\n");
    }
}

void usage() {
  printf("syntax: pcap_test <interface>\n");
  printf("sample: pcap_test wlan0\n");
}

int main(int argc, char* argv[]) {
  if (argc != 2) {
    usage();
    return -1;
  }
    int ilen = 0;
    int thlen = 0;
    int offeset =0;
  char* dev = argv[1];
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
  }

  while (true) {
    struct pcap_pkthdr* header;
    const u_char* packet;
    int res = pcap_next_ex(handle, &header, &packet);
    if (res == 0) continue;
    if (res == -1 || res == -2) break;

    printf("%u bytes captured\n", header->caplen);
    printf("D-Mac : ");
    print_mac(&packet[0]);
    printf("S-Mac : ");
    print_mac(&packet[6]);
    printf("Type :");
    print_type(&packet[12]);
     if(Z==1){
    printf("S-IP : ");
    print_ip(&packet[14 + 12]);
    printf("D-IP : ");
    print_ip(&packet[14 + 16]);
    printf("protocol : ");
    ipcheck(&packet[23]);
    ilen = 4*start_tcp(&packet[14]);
    //packet[len+13]; start TCP
    offeset = ilen +13+1;
    printf("S-Port : ");
    print_port(&packet[offeset]);
    printf("D-Port : ");
    print_port(&packet[offeset+2]);
    thlen = 4*start_http(&packet[offeset+12]);
    int tl = ((packet[16]<<8)|packet[17])-(ilen+thlen);//packet[46];
    //tcp payload is total length - (ip+tcp);
    printf("TCP DATA size : %d \n",tl);
    printf("===========TCP DATA============\n");
    print_Tcpdata(&packet[ilen+thlen+13],tl);
    printf("\n\n");
    }
  }

  pcap_close(handle);
  return 0;
}
