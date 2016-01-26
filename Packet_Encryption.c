
/*
* Copyright (C) <2015>  <Han Zhang>

* BotTalker is free software: you can redistribute it and/or modify 
* it under the terms of the GNU General Public License as published 
* by the Free Software Foundation, either version 3 of the License, 
* or (at your option) any later version.

* BotTalker is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
* GNU General Public License for more details.

* You should have received a copy of the GNU General Public License
* along with this program.  If not, see <http://www.gnu.org/licenses/>.

* Contact information:
* Email: zhanghan0116@gmail.com
*/

/*
Encrypt individual packet's payload
1. The encrypted payload size doesn't change: XOR, CFB, OFB
	Encrypt payload and put the encrypted payload back to packet
2. The encrypted payload size changes: ECB, CBC
	Step1: Encrypt payload
	Step2: Trim the encrypted payload as the same size of original payload size
	Step3: Put trimmed encrypted payload back to packet
*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include <time.h>
#include "libtrace.h"
#include <stdio.h> 
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include "BotTalkerFunctions.c"

#define MAX_SIZE 1024

int oriSubnet = 32;
int replaceSubnet = 32;
int enableIPAnonymize = 0;	//1 means the ip needs to be anonymized
int enablePortFilter = 0;	//1 means the port needs to be filtered
int enableEncryption = 0;		//1 means the data needs to be encrypted
int enableKeyIV = 0;
int encryptAll = 0;		//encrypt all the traffic, otherwise encrypt a specific flow
int enableEncryptExecutable = 0;	//1 means use the executable magic number files
int enableReplaceIP = 0;		//apply IP replacement
int enableReplaceCertainIP = 0;
int enableReplaceAllIP = 0;
char oriIP[16];		//original IP
char replaceIP[16];		//new IP 
char encryptionAlgorithm[32];	//specify the encryption algorithm
extern struct flow_record * flowExtractHead;
extern struct flow_record * flowExtractLast;
extern struct ip_list * ipExclusion;
extern struct port_list * portExclusion;
//struct flow_rtt_inter flow_stats = {0, "129.82.138.45", 52424, "129.82.138.36", 60000, 0, 0, -1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

static int per_packet(libtrace_packet_t * pkt, libtrace_out_t * wr, char * key, char *iv, char * encryptionAlgorithm)
{
	EVP_CIPHER_CTX ctx;

	if(enableEncryption == 1)
	{
		if( strcmp(encryptionAlgorithm, "xor") != 0 )
		{
			set_encryption_algorithm(encryptionAlgorithm, &ctx, key, iv);
		}
	}

	// Create a new packet which is a copy of the old packet.
	libtrace_packet_t *copyPkt = trace_copy_packet(pkt);
	libtrace_ip_t *ip = trace_get_ip(copyPkt);
	libtrace_ip6_t *ip6 = trace_get_ip6(copyPkt);

	struct flow_record * iteFlowRecord;
	struct sockaddr_storage src_addr;
	struct sockaddr_storage dest_addr;
	struct sockaddr *src_addr_ptr;
	struct sockaddr *dest_addr_ptr;
	/* Packet data */
	uint32_t remaining;
	/* L3 data */
	void *l3;
	uint16_t ethertype;
	/* Transport data */
	void *transport;
	uint8_t proto;
	/* Payload data */
	void *payload;

	int i = 0;
	int pktSize;
	char srcIP[100];
	char destIP[100];
	char *ct, *out;
	char * encryptedContent = NULL;
	char final[EVP_MAX_BLOCK_LENGTH];
	struct timeval ts;

	l3 = trace_get_layer3(copyPkt,&ethertype,&remaining);

	if (!l3)
	{
		/* Probable ARP or something */
		return;
	}

	/* Get the UDP/TCP/ICMP header from the IPv4/IPv6 packet */
	switch (ethertype) {
		case 0x0800:
			transport = trace_get_payload_from_ip(
					(libtrace_ip_t*)l3,
					&proto,
					&remaining);
			if (!transport)
				return;
			//++v4;
			break;
		case 0x86DD:
			transport = trace_get_payload_from_ip6(
					(libtrace_ip6_t*)l3,
					&proto,
					&remaining);
			if (!transport)
				return;
			//++v6;
			break;
		default:
			return;
	}

	// Get packet information
	//get port numbers
	int srcPort = trace_get_source_port(copyPkt);
	int destPort = trace_get_destination_port(copyPkt);
	src_addr_ptr = trace_get_source_address(copyPkt, (struct sockaddr *) &src_addr);
	dest_addr_ptr = trace_get_destination_address(copyPkt, (struct sockaddr *) &dest_addr);
	if( (NULL == src_addr_ptr) || (NULL == dest_addr_ptr) )
	{
		return;
	}
	//get source ip address
	if (src_addr_ptr->sa_family == AF_INET) {
		struct sockaddr_in *src_v4 = (struct sockaddr_in *) src_addr_ptr;
		inet_ntop(AF_INET, &(src_v4->sin_addr), srcIP, 100);
	}
	//get destination ip address
	if (dest_addr_ptr->sa_family == AF_INET) {
		struct sockaddr_in *dest_v4 = (struct sockaddr_in *) dest_addr_ptr;
		inet_ntop(AF_INET, &(dest_v4->sin_addr), destIP, 100);
	}

	if( (CheckExclusionPort(srcPort)==1) || (CheckExclusionPort(destPort)==1) )
	{
		goto IP_Replace;
	}

	ts = trace_get_timeval(copyPkt);
	pktSize = trace_get_capture_length(copyPkt);

	if(enableEncryption == 1)
	{
		iteFlowRecord = flowExtractHead;
		while(iteFlowRecord)
		{
			if( (encryptAll == 0) && (proto == iteFlowRecord->proto) && ( ( (srcPort == iteFlowRecord->src_port) && (strcmp( srcIP, iteFlowRecord->src_ip) == 0) && (destPort == iteFlowRecord->dest_port) && (strcmp(destIP, iteFlowRecord->dest_ip) == 0) ) || ( (destPort == iteFlowRecord->src_port) && (strcmp(destIP, iteFlowRecord->src_ip ) == 0) && (srcPort == iteFlowRecord->dest_port) && (strcmp(srcIP, iteFlowRecord->dest_ip) == 0 ) ) ) )
			{
				break;
			}
			iteFlowRecord = iteFlowRecord->next;
		}
		if( (iteFlowRecord != NULL) || (encryptAll == 1) )
		{
			if(proto == 17)	//udp
			{
				payload = trace_get_payload_from_udp( (libtrace_udp_t*)transport, &remaining);
				char * temp = (char*)transport+sizeof(libtrace_udp_t);
				int dataLen = ntohs(((libtrace_udp_t*) transport)->len)-8;
				struct libtrace_udp *udp;
				udp=trace_get_udp_from_ip(ip,NULL);
				//encrypt the payload
				char payloadCopy[dataLen+1];
				char payloadEncryptCopy[dataLen+1];
				memset(payloadCopy, '\0', sizeof(payloadCopy));
				memset(payloadEncryptCopy, '\0', sizeof(payloadEncryptCopy));
				if(dataLen > 0)
				{
					memcpy(payloadCopy, temp, dataLen);
					if( strcmp(encryptionAlgorithm, "xor") == 0 )
					{
						encryptedContent = (char *)malloc(dataLen * sizeof(char));
						encrypt_xor(payloadCopy, encryptedContent, key, dataLen);
					}
					else
					{
						encryptedContent = encrypt_OpenSSL(&ctx, payloadCopy, dataLen, &i);
					}
					memcpy(transport+sizeof(libtrace_udp_t), encryptedContent, dataLen);
					memcpy(payloadEncryptCopy, encryptedContent, dataLen);
					payload_checksum(&udp->check, payloadCopy, payloadEncryptCopy, dataLen);
					if( strcmp(encryptionAlgorithm, "xor") == 0 )
					{
						free(encryptedContent);
					}
				}
			}

			if(proto == 6)	//tcp
			{
				payload = trace_get_payload_from_tcp( (libtrace_tcp_t*)transport, &remaining);
				int dlen = ((libtrace_tcp_t*) transport)->doff*4;
				int dataLen = ntohs(ip->ip_len)-dlen-4*(ip->ip_hl);
				char * temp = ((char *)transport+dlen);
				char payloadCopy[dataLen+1];
				char payloadEncryptCopy[dataLen+1];
				memset(payloadCopy, '\0', sizeof(payloadCopy));
				memset(payloadEncryptCopy, '\0', sizeof(payloadEncryptCopy));
				if(dataLen>0)
				{
					struct libtrace_tcp *tcp;
					tcp=trace_get_tcp_from_ip(ip,NULL);
					//update_in_cksum32(&tcp->ip_sum, old_ip, htonl(new_ip));
					memcpy(payloadCopy, temp, dataLen);
					if( strcmp(encryptionAlgorithm, "xor") == 0 )
					{
						encryptedContent = (char *)malloc( (dataLen) * sizeof(char));
						encrypt_xor(payloadCopy, encryptedContent, key, dataLen);
					}
					else
					{
						encryptedContent = encrypt_OpenSSL(&ctx, payloadCopy, dataLen, &i);
					}
					memcpy(transport+sizeof(libtrace_tcp_t), encryptedContent, dataLen);
					memcpy(payloadEncryptCopy, encryptedContent, dataLen);
					payload_checksum(&tcp->check, payloadCopy, payloadEncryptCopy, dataLen);
					if( strcmp(encryptionAlgorithm, "xor") == 0 )
					{
						free(encryptedContent);
					}
				}
			}
		}
	}

IP_Replace:

	if(enableReplaceIP == 1)
	{
		if(enableReplaceAllIP == 1)	//replace all the external ip addresses
		{
			if(CheckExclusionIP(srcIP)==0)	//replace src ip
			{
				ReplaceIP_All(ip, oriIP, replaceIP, oriSubnet, replaceSubnet, 0);
			}
			if(CheckExclusionIP(destIP)==0)	//replace dest ip
			{
				ReplaceIP_All(ip, oriIP, replaceIP, oriSubnet, replaceSubnet, 1);
			}
		}
		if(enableReplaceCertainIP == 1)	//replace certain ip addresses
		{
			if(CheckExclusionIP(srcIP)==0)	//replace src ip
			{
				ReplaceIP(ip, oriIP, replaceIP, oriSubnet, 0);
			}
			if(CheckExclusionIP(destIP)==0)	//replace dest ip
			{
				ReplaceIP(ip, oriIP, replaceIP, oriSubnet, 1);
			}
		}
	}

	if (trace_write_packet(wr, copyPkt) == -1)
	{
		trace_perror_output(wr, "Writing packet");
		return -1;
	}
	trace_destroy_packet(copyPkt);
	return 0;
}

int main(int argc, char *argv[])
{
	EVP_CIPHER_CTX ctx;
	FILE * fpKeyIV = NULL;
	char * key = NULL;
	char * iv;
	char * p = NULL;
	clock_t start;
	clock_t end;
	double cost;
	int opt = 0;
	int psize = 0;
	int pktCount = 0;
	int keyBytesCount = 0;
	int ivBytesCount = 0;
	int cipherBlockSize = 0;
	int cipherKeySize = 0;
	int cipherIVSize = 0;
	char bufferTemp[MAX_SIZE];
	char keyIVBuffer[MAX_SIZE];
	char keyIVTemp[MAX_SIZE];
	char IPReplaceFile[MAX_SIZE];
	char encryption[MAX_SIZE];
	char ipExclusionFile[MAX_SIZE];
	char portExclusionFile[MAX_SIZE];
	int enableIPExclusion = 0;
	int enablePortExclusion = 0;
	char flowsFile[MAX_SIZE];
	char inputFile[MAX_SIZE];
	char outputFile[MAX_SIZE];
	char keyIVFile[MAX_SIZE];
	char encryptionAlgorithm[16];
	char exeMagicNumberFile[MAX_SIZE];
	char oriReplaceIP[MAX_SIZE];

	if ((argc - optind) < 1) {
		usage();
		exit(1);
	}

	while ((opt = getopt(argc, argv, "a:d:e:f:k:i:nNo:r:")) !=-1)
	{
		switch (opt)
		{
			case 'a':
				strcpy(ipExclusionFile, optarg);
				enableIPExclusion = 1;
				break;
			case 'd':
				strcpy(portExclusionFile, optarg);
				enablePortExclusion = 1;
				break;
			case 'i':
				strcpy(inputFile, optarg);
				break;
			case 'o':
				strcpy(outputFile, optarg);
				break;
			case 'k':
				enableKeyIV = 1;
				strcpy(keyIVFile, optarg);
				break;
			case 'e':
				enableEncryption = 1;
				strcpy(encryptionAlgorithm, optarg);
				printf("encryptionAlgorithm: %s\n", encryptionAlgorithm);
				break;
			case 'f':
				/*encrypt all the traffic*/
				if(strcmp("all", optarg) == 0)
				{
					encryptAll = 1;
					printf("Encrypt all the traffic\n");
				}
				else
				{
					strcpy(flowsFile, optarg);
				}
				break;
			case 'n':
				enableReplaceCertainIP = 1;
				break;
			case 'N':
				enableReplaceAllIP = 1;
				break;
			case 'r':
				enableReplaceIP = 1;
				strcpy(oriReplaceIP, optarg);
				p = NULL;
				p = strtok(oriReplaceIP, "/");
				if(p)
				{
					strcpy(oriIP, p);
				}
				p = strtok(NULL, " ");
				if(p)
				{
					oriSubnet = atoi(p);
				}
				p = strtok(NULL, "/");
				if(p)
				{
					strcpy(replaceIP, p);
				}
				p = strtok(NULL, " ");
				if(p)
				{
					replaceSubnet = atoi(p);
				}
				//printf("ori_ip: %s, ori_subnet: %d, replace_ip: %s, replace_subnet: %d\n", oriIP, oriSubnet, replaceIP, replaceSubnet);
				break;
			case 'h':
				usage();
				exit(1);
			default:
				usage();
				exit(1);
		}
	}

	time(&start);

	if(enableIPExclusion == 1)
	{
		ReadIPExclusionRecords(ipExclusionFile);
	}
	if(enablePortExclusion == 1)
	{
		ReadPortExclusionRecords(portExclusionFile);
	}
	if(enableKeyIV == 1)
	{
		if(encryptAll != 1)
		{
			ReadFlowRecords(flowsFile);
		}
		//extract key and iv
		if((fpKeyIV = fopen(keyIVFile, "r")) == NULL)  //open the file to read
		{
			fprintf(stderr, "Read key and iv file: %s failed\n", keyIVFile);
			exit(1);
		}
		//read and parse the key
		memset(keyIVBuffer, '\0', sizeof(keyIVBuffer));
		fgets(keyIVBuffer, sizeof(keyIVBuffer), fpKeyIV);
		key = (char *)malloc(sizeof(char) * strlen(keyIVBuffer));
		strcpy(key, keyIVBuffer);
		memset(key+strlen(keyIVBuffer)-1, '\0', 1);
		printf("key: %s\n", key);
		//read and parse the iv
		memset(keyIVBuffer, '\0', sizeof(keyIVBuffer));
		if( fgets(keyIVBuffer, sizeof(keyIVBuffer), fpKeyIV) != NULL )
		{
			iv = (char *)malloc(sizeof(char) * strlen(keyIVBuffer));
			strcpy(iv, keyIVBuffer);
			memset(iv+strlen(iv)-1, '\0', 1);
			printf("iv: %s\n", iv);
		}
	}

	libtrace_t *trace = 0;
	libtrace_out_t *writer = 0;
	libtrace_packet_t *pkt = trace_create_packet();

	// Open traces for reading and writing.
	trace = trace_create(inputFile);
	if (trace_is_err(trace)) {
		trace_perror(trace, "trace_create");
		trace_destroy(trace);
		return 1;
	}
	if (trace_start(trace) == -1) {
		trace_perror(trace,"Starting trace");
		//libtrace_cleanup(trace, output, packet);
		return 1;
	}

	//writer = trace_create_output("pcap:testcp");
	writer = trace_create_output(outputFile);
	if (trace_is_err_output(writer)) {
		trace_perror_output(writer, "trace_create_output");
		trace_destroy_output(writer);
		trace_destroy(trace);
		trace_destroy_packet(pkt);
		return 1;
	}

	if (trace_start_output(writer) == -1) {
		trace_perror_output(writer,"Starting output trace");
		//libtrace_cleanup(trace, output, packet);
		return 1;
	}

	//encrypt traffic and write to new file
	for (;;) {
		psize = trace_read_packet(trace, pkt);
		if (psize == 0) {
			break;
		}
		if (psize < 0) {
			trace_perror(trace, "read_packet");
			break;
		}
		//if(pkt_count < 50)
		{
			if ((per_packet(pkt, writer, key, iv, encryptionAlgorithm)) == -1)
			{
				fprintf(stderr, "Something went wrong in per_packet.\n");
				break;
			}
		}
		pktCount++;
	}

	trace_destroy_packet(pkt);
	trace_destroy(trace);
	trace_destroy_output(writer);

	time(&end);
	cost = difftime(end, start);
	printf("running time: %f\n", cost);

	return 0;
}
