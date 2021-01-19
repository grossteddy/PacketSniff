#include<stdio.h>	//For standard things
#include<string.h>	//For strcpy
#include<netinet/ip_icmp.h>	//Provides declarations for icmp header
#include<netinet/ip.h>	//Provides declarations for ip header
#include<sys/socket.h>
#include<arpa/inet.h>

#define MAX_IP_LEN 16
#define PACKET_BUFFER_SIZE 65536

void ProcessPacket(unsigned char* , int);
void print_icmp_packet(unsigned char* , int);

int sock_raw;

struct sockaddr_in source,dest;

int main()
{
	int saddr_size , data_size;
	struct sockaddr saddr;
	
	unsigned char buffer[PACKET_BUFFER_SIZE] = {0};
	
	printf("Starting...\n");
	//Create a raw socket that shall sniff
	sock_raw = socket(AF_INET , SOCK_RAW , IPPROTO_ICMP);
	if(sock_raw < 0)
	{
		printf("Socket Error\n");
		return 1;
	}
	while(1)
	{
		saddr_size = sizeof saddr;
		//Receive a packet
		data_size = recvfrom(sock_raw , buffer , sizeof(buffer) , 0 , &saddr , &saddr_size);
		if(data_size < 0)
		{
			printf("Recvfrom error , failed to get packets\n");
			return 1;
		}
		
		//Now process the packet
		ProcessPacket(buffer , data_size);
		
	}
	close(sock_raw);
	printf("Finished");
	return 0;
}

void ProcessPacket(unsigned char* buffer, int size)
{
	//Get the IP Header part of this packet
	struct iphdr *iph = (struct iphdr*)buffer;
	
	if ((iph->protocol) == 1) //Check the Protocol and do accordingly...
	{	
		print_icmp_packet(buffer , size);
	}
    else 
    {
        printf("ProcessPacket error");
    }
}

void print_icmp_packet(unsigned char* Buffer , int Size)
{
	unsigned short iphdrlen;
	
	struct iphdr *iph = (struct iphdr *)Buffer;
	iphdrlen = iph->ihl*4;
	
	struct icmphdr *icmph = (struct icmphdr *)(Buffer + iphdrlen);

    struct sockaddr_in src_ip = { 0 };
	src_ip.sin_addr.s_addr = iph->saddr;
	char src_ip_str[MAX_IP_LEN] = { 0 };
	strcpy(src_ip_str, inet_ntoa(src_ip.sin_addr)); 

	struct sockaddr_in dst_ip = { 0 };
	dst_ip.sin_addr.s_addr = iph->daddr;
	char dst_ip_str[MAX_IP_LEN] = { 0 };
	strcpy(dst_ip_str, inet_ntoa(dst_ip.sin_addr));
	
    printf("ICMP PACKET\n");

	printf("IP SRC: %s  --->  IP Dest: %s\n",src_ip_str, dst_ip_str);
		
	printf("Type: %d\n",(unsigned int)(icmph->type));
			
	printf("Code: %d\n",(unsigned int)(icmph->code));

    printf("\n");	
}