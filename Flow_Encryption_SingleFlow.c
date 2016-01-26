
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
Encryption Algorithm
	Encrypted data size doesn't change: XOR, CFB, OFB
1. Read flow payload from file
2. encrypt data
3. put encrypted data back into packets
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
int enableReplaceCertainIP = 0;
int enableReplaceAllIP = 0;
int encryptAll = 0;		//encrypt all the traffic, otherwise encrypt a specific flow
int enableEncryptExecutable = 0;	//1 means use the executable magic number files
int enableReplaceIP = 0;		//apply IP replacement
char oriIP[16];		//original IP
char replaceIP[16];		//new IP 
char encryptionAlgorithm[32];	//specify the encryption algorithm
struct flow_record flowExtract;
//struct flow_rtt_inter flow_stats = {0, "129.82.138.45", 52424, "129.82.138.36", 60000, 0, 0, -1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

static int per_packet_write_to_file(libtrace_packet_t * pkt, struct flow_record * flowExtract)
{
	// Create a new packet which is a copy of the old packet.
	//libtrace_packet_t *copy_pkt = trace_copy_packet(pkt);
	libtrace_ip_t *ip = trace_get_ip(pkt);
	libtrace_ip6_t *ip6 = trace_get_ip6(pkt);

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
	int loop = 0;
	char srcIP[100];
	char destIP[100];
	struct timeval ts;

	l3 = trace_get_layer3(pkt,&ethertype,&remaining);

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
	int srcPort = trace_get_source_port(pkt);
	int destPort = trace_get_destination_port(pkt);
	src_addr_ptr = trace_get_source_address(pkt, (struct sockaddr *) &src_addr);
	dest_addr_ptr = trace_get_destination_address(pkt, (struct sockaddr *) &dest_addr);
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

	ts = trace_get_timeval(pkt);
	
	if( (proto == 17) || (proto == 6) )
	{
		char * temp;
		char * payloadCopy;
		int dlen = 0;
		int dataLen = 0;
		/* Parse the udp/tcp/icmp payload */
		if(proto == 17)	//udp
		{
			payload = trace_get_payload_from_udp( (libtrace_udp_t*)transport, &remaining);
			dataLen = ntohs(((libtrace_udp_t*) transport)->len)-8;
			temp = (char*)transport+sizeof(libtrace_udp_t);
			//encrypt the payload
			payloadCopy = (char *)malloc(dataLen+1);
		}
		if(proto == 6)	//tcp
		{
			payload = trace_get_payload_from_tcp( (libtrace_tcp_t*)transport, &remaining);
			dlen = ((libtrace_tcp_t*) transport)->doff*4;
			dataLen = ntohs(ip->ip_len)-dlen-4*(ip->ip_hl);
			//char * temp = (char *)payload;
			temp = ((char *)transport+dlen);
			payloadCopy = (char *)malloc(dataLen+1);
		}

		memset(payloadCopy, '\0', sizeof(payloadCopy));
		memcpy(payloadCopy, temp, dataLen);
		//check whether there is a HTTP header
		if( (proto == flowExtract->proto) && (srcPort == flowExtract->src_port) && (strcmp(srcIP, flowExtract->src_ip) == 0) && (destPort == flowExtract->dest_port) && (strcmp(destIP, flowExtract->dest_ip) == 0) )
		{
			//printf("src_ip: %s, src_port: %d, dst_ip: %s, dst_port: %d, remaining: %d\n", src_ip, src_port, dest_ip, dest_port, remaining);
			if(flowExtract->last_direction == -1)
			{
				//printf("line: %d, remaining: %d\n", __LINE__, remaining);
				flowExtract->last_direction = 0;
				flowExtract->current_offset = dataLen;
			}
			else if(flowExtract->last_direction == 1)
			{
				//printf("line: %d\n", __LINE__);
				fprintf(flowExtract->fp_offset, "%d\n", flowExtract->current_offset);
				flowExtract->last_direction = 0;
				flowExtract->current_offset = dataLen;
				flowExtract->offset_count++;
			}
			else if(flowExtract->last_direction == 0)
			{
				//printf("line: %d, remaining: %d\n", __LINE__, remaining);
				flowExtract->current_offset = flowExtract->current_offset + dataLen;
			}
			if(flowExtract->current_offset > flowExtract->offset_max)
			{
				flowExtract->offset_max = flowExtract->current_offset;
			}
			flowExtract->flow_size = flowExtract->flow_size + dataLen;
			fwrite(payloadCopy, sizeof(char), dataLen, flowExtract->fp_content);
		}
		if ( (proto == flowExtract->proto) && (destPort == flowExtract->src_port) && (strcmp(destIP, flowExtract->src_ip ) == 0) && (srcPort == flowExtract->dest_port) && (strcmp(srcIP, flowExtract->dest_ip) == 0 ) )
		{
			//printf("src_ip: %s, src_port: %d, dst_ip: %s, dst_port: %d, remaining: %d\n", src_ip, src_port, dest_ip, dest_port, remaining);
			if(flowExtract->last_direction == -1)
			{
				//printf("line: %d\n", __LINE__);
				flowExtract->last_direction = 1;
				flowExtract->current_offset = dataLen;
			}
			else if(flowExtract->last_direction == 0)
			{
				//printf("line: %d, remaining: %d\n", __LINE__, remaining);
				fprintf(flowExtract->fp_offset, "%d\n", flowExtract->current_offset);
				flowExtract->last_direction = 1;
				flowExtract->current_offset = dataLen;
				flowExtract->offset_count++;
			}
			else if(flowExtract->last_direction == 1)
			{
				//printf("line: %d, remaining: %d\n", __LINE__, remaining);
				flowExtract->current_offset = flowExtract->current_offset + dataLen;
			}
			if(flowExtract->current_offset > flowExtract->offset_max)
			{
				flowExtract->offset_max = flowExtract->current_offset;
			}
			flowExtract->flow_size = flowExtract->flow_size + dataLen;
			fwrite(payloadCopy, sizeof(char), dataLen, flowExtract->fp_content);
		}
		//free(payload_copy);
	}
	return 0;
}




static int per_packet_overwrite(libtrace_packet_t * pkt, libtrace_out_t * wr, char * data_to_trace, int * offset, struct flow_record * flowExtract)
{
	//EVP_CIPHER_CTX ctx;
	// Create a new packet which is a copy of the old packet.
	libtrace_packet_t *copyPkt = trace_copy_packet(pkt);
	libtrace_ip_t *ip = trace_get_ip(copyPkt);
	libtrace_ip6_t *ip6 = trace_get_ip6(copyPkt);

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

	struct timeval ts;
	char srcIP[100];
	char destIP[100];
	int loop = 0;

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

	ts = trace_get_timeval(copyPkt);
	//int pkt_size = trace_get_capture_length(copy_pkt);
	
	if(enableEncryption == 1)
	{
		if(proto == 17)	//udp
		{
			payload = trace_get_payload_from_udp( (libtrace_udp_t*)transport, &remaining);
			char * temp = (char*)transport+sizeof(libtrace_udp_t);
			int dataLen = ntohs(((libtrace_udp_t*) transport)->len)-8;
			if(dataLen == 0)
			{
				goto WRITE;
			}
			struct libtrace_udp *udp;
			udp=trace_get_udp_from_ip(ip,NULL);
			//encrypt the payload
			char payloadCopy[dataLen+1];
			char payloadEncryptCopy[dataLen+1];
			memset(payloadCopy, '\0', sizeof(payloadCopy));
			memset(payloadEncryptCopy, '\0', sizeof(payloadEncryptCopy));
			memcpy(payloadCopy, temp, dataLen);
			if( (proto == flowExtract->proto) && ( ( (srcPort == flowExtract->src_port) && (strcmp(srcIP, flowExtract->src_ip) == 0) && (destPort == flowExtract->dest_port) && (strcmp(destIP, flowExtract->dest_ip) == 0) ) || ( (destPort == flowExtract->src_port) && (strcmp(destIP, flowExtract->src_ip ) == 0) && (srcPort == flowExtract->dest_port) && (strcmp(srcIP, flowExtract->dest_ip) == 0 ) ) ) )
			{
				memcpy(transport+sizeof(libtrace_udp_t), data_to_trace+flowExtract->current_offset, dataLen);
				memcpy(payloadEncryptCopy, data_to_trace+flowExtract->current_offset, dataLen);
				payload_checksum(&udp->check, payloadCopy, payloadEncryptCopy, dataLen);
				flowExtract->current_offset = flowExtract->current_offset + dataLen;
				//printf("Line: %d, remaining: %d, offset: %d\n", __LINE__, remaining, *offset);
			}
		}

		if(proto == 6)	//tcp
		{
			payload = trace_get_payload_from_tcp( (libtrace_tcp_t*)transport, &remaining);
			int dlen = ((libtrace_tcp_t*) transport)->doff*4;
			int dataLen = ntohs(ip->ip_len)-dlen-4*(ip->ip_hl);
			//char * temp = (char *)payload;
			char * temp = ((char *)transport+dlen);
			char payloadCopy[dataLen+1];
			char payloadEncryptCopy[dataLen+1];
			memset(payloadCopy, '\0', sizeof(payloadCopy));
			memset(payloadEncryptCopy, '\0', sizeof(payloadEncryptCopy));
			struct libtrace_tcp *tcp;
			tcp=trace_get_tcp_from_ip(ip,NULL);

			if(dataLen == 0)
			{
				goto WRITE;
			}
			memcpy(payloadCopy, temp, dataLen);
			if( (proto == flowExtract->proto) && ( ( (srcPort == flowExtract->src_port) && (strcmp(srcIP, flowExtract->src_ip) == 0) && (destPort == flowExtract->dest_port) && (strcmp(destIP, flowExtract->dest_ip) == 0) ) || ( (destPort == flowExtract->src_port) && (strcmp(destIP, flowExtract->src_ip ) == 0) && (srcPort == flowExtract->dest_port) && (strcmp(srcIP, flowExtract->dest_ip) == 0 ) ) ) )
			{
				//memcpy(transport+sizeof(libtrace_tcp_t), data_to_trace+*offset, remaining);
				memcpy(transport+sizeof(libtrace_tcp_t), data_to_trace+flowExtract->current_offset, dataLen);
				memcpy(payloadEncryptCopy, data_to_trace+flowExtract->current_offset, dataLen);
				payload_checksum(&tcp->check, payloadCopy, payloadEncryptCopy, dataLen);

				flowExtract->current_offset = flowExtract->current_offset + dataLen;
				//printf("Line: %d, offset: %d\n", __LINE__, *offset);
			}
		}
	}

WRITE:
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

		//ReplaceIP(ip, ori_ip, replace_ip, ori_subnet);
	}

	if (trace_write_packet(wr, copyPkt) == -1) {
		trace_perror_output(wr, "Writing packet");
		return -1;
	}
	trace_destroy_packet(copyPkt);
	return 0;
}

int main(int argc, char *argv[])
{
	EVP_CIPHER_CTX ctx;
	char * p = NULL;
	char * key = NULL;
	char * iv = NULL;
	//char * file_content = NULL;
	//char * encrypted_file_content;
	FILE * fpKeyIV = NULL;
	FILE * fpFlowPayload = NULL;
	int i = 0;
	int opt = 0;
	int psize = 0;
	int pktCount = 0;
	int offset = 0;
	int filesize = 0;
	int readLength = 0;
	int traceOffset = 0;
	int ivBytesCount = 0;
	int keyBytesCount = 0;
	int enableIPExclusion = 0;
	char tempRead[100];
	char keyIVBuffer[1024];
	char ipExclusionFile[MAX_SIZE];
	char IPReplaceFile[MAX_SIZE];
	char encryption[MAX_SIZE];
	char portFilterFile[MAX_SIZE];
	char inputFile[MAX_SIZE];
	char outputFile[MAX_SIZE];
	char keyIVFile[MAX_SIZE];
	char encryptionAlgorithm[16];
	char exeMagicNumberFile[MAX_SIZE];
	char flowPayloadFile[256];
	char flowOffsetFile[256];
	char oriReplaceIP[MAX_SIZE];
	char bufferTemp[MAX_SIZE];
	clock_t start;
	clock_t end;
	double functionTime;

	if ((argc - optind) < 1) {
		usage();
		exit(1);
	}

	while ((opt = getopt(argc, argv, "a:e:f:k:i:nNo:r:")) !=-1)
	{
		switch (opt)
		{
			case 'a':
				strcpy(ipExclusionFile, optarg);
				enableIPExclusion = 1;
				break;
			case 'n':
				enableReplaceCertainIP = 1;
				break;
			case 'N':
				enableReplaceAllIP = 1;
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
				break;
			case 'f':
				/*encrypt all the traffic*/
				if(strcmp("all", optarg) == 0)
				{
					encryptAll = 1;
				}
				else
				{
					p = NULL;
					p = strtok(optarg, " ");
					if(p)
					{
						strcpy(flowExtract.src_ip, p);
					}
					p = strtok(NULL, " ");
					if(p)
					{
						flowExtract.src_port = atoi(p);
					}
					p = strtok(NULL, " ");
					if(p)
					{
						strcpy(flowExtract.dest_ip, p);
					}
					p = strtok(NULL, " ");
					if(p)
					{
						flowExtract.dest_port = atoi(p);
					}
					p = strtok(NULL, " ");
					if(p)
					{
						flowExtract.proto = atoi(p);
					}
				}
				//printf("src_ip: %s, src_port: %d, dest_ip: %s, dest_port: %d, proto: %d\n", flow_extract.src_ip, flow_extract.src_port, flow_extract.dest_ip, flow_extract.dest_port, flow_extract.proto);
				break;
				//struct flow_record flow_extract = {"192.168.9.5", 1035, "178.162.181.84", 80};
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

	libtrace_t *trace = 0;
	libtrace_packet_t *pkt = trace_create_packet();

	if(enableIPExclusion == 1)
	{
		ReadIPExclusionRecords(ipExclusionFile);
	}

	if(enableEncryption == 1)
	{
		//write the flow payload to file
		memset(flowPayloadFile, '\0', sizeof(flowPayloadFile));
		sprintf(flowPayloadFile, "%s-%d-%s-%d-%d-flow-payload", flowExtract.src_ip, flowExtract.src_port, flowExtract.dest_ip, flowExtract.dest_port, flowExtract.proto);
		sprintf(flowOffsetFile, "%s-%d-%s-%d-%d-flow-offset", flowExtract.src_ip, flowExtract.src_port, flowExtract.dest_ip, flowExtract.dest_port, flowExtract.proto);
		if((flowExtract.fp_content = fopen(flowPayloadFile, "w+")) == NULL)  //open the file to read
		{
			fprintf(stderr, "Open file: %s failed\n", flowPayloadFile);
			exit(1);
		}
		if((flowExtract.fp_offset = fopen(flowOffsetFile, "w+")) == NULL)  //open the file     to read
		{
			fprintf(stderr, "Open file: %s failed\n", flowOffsetFile);
			exit(1);
		}
		flowExtract.current_offset = 0;
		flowExtract.offset_max = 0;
		flowExtract.last_direction = -1;
		flowExtract.flow_size = 0;
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

		for (;;) {
			psize = trace_read_packet(trace, pkt);
			if (psize == 0) {
				break;
			}
			if (psize < 0) {
				trace_perror(trace, "read_packet");
				break;
			}
			if ((per_packet_write_to_file(pkt, &flowExtract)) == -1)
			{
				fprintf(stderr, "Something went wrong in per_packet.\n");
				break;
			}
			pktCount++;
		}
		pktCount = 0;
		fprintf(flowExtract.fp_offset, "%d\n", flowExtract.current_offset);
		flowExtract.offset_count++;
		fclose(flowExtract.fp_content);
		fclose(flowExtract.fp_offset);
		 
		flowExtract.offset_array = (int *)malloc(sizeof(int) * flowExtract.offset_count);
		//fseek(flow_extract.fp_offset, 0, SEEK_END);
		int counter = 0;
		if((flowExtract.fp_offset = fopen(flowOffsetFile, "r")) == NULL)  //open the file     to read
		{
			fprintf(stderr, "Open file: %s failed\n", flowOffsetFile);
			exit(1);
		}
		while(counter < flowExtract.offset_count)
		{
			memset(tempRead, '\0', sizeof(tempRead));
			fgets(tempRead, sizeof(tempRead), flowExtract.fp_offset);
			flowExtract.offset_array[counter] = atoi(tempRead);
			//printf("offset: %d\n", flow_extract.offset_array[counter]);
			counter++;
		}
		fclose(flowExtract.fp_offset);
		//end of write flow payload to file

		//strcpy(flow_payload_file, flow_payload_file);
		//read original data from file
		if((flowExtract.fp_content = fopen(flowPayloadFile, "r")) == NULL)  //open the file     to read
		{
			fprintf(stderr, "Open file: %s failed\n", flowPayloadFile);
			exit(1);
		}
		//printf("File %s has %d bytes\n", flowPayloadFile, flowExtract.flow_size);

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

		flowExtract.encrypted_file_content = (char *)malloc(sizeof(char) * flowExtract.flow_size);
		flowExtract.temp_file_content = (char *)malloc(sizeof(char) * flowExtract.offset_max);
		flowExtract.temp_encrypted_content = (char *)malloc(sizeof(char) * flowExtract.offset_max);
		counter = 0;
		offset = 0;
		memset(flowExtract.encrypted_file_content, '\0', sizeof(flowExtract.encrypted_file_content));
		while(counter < flowExtract.offset_count)
		{
			memset(flowExtract.temp_file_content, '\0', sizeof(flowExtract.temp_file_content));
			fread(flowExtract.temp_file_content, flowExtract.offset_array[counter], 1, flowExtract.fp_content);
			//printf("should read: %d, read: %d\n", flow_extract.offset_array[counter], read_length);
			//memcpy(flow_extract.encrypted_file_content + offset, flow_extract.temp_file_content, flow_extract.offset_array[counter]);
			//encrypt data read from file
			if( strcmp(encryptionAlgorithm, "xor") == 0 )
			{
				//encrypted_file_content = (char *)malloc(sizeof(char) * filesize);
				encrypt_xor(flowExtract.temp_file_content, flowExtract.temp_encrypted_content, key, flowExtract.offset_array[counter]);
			}
			else
			{
				set_encryption_algorithm(encryptionAlgorithm, &ctx, key, iv);
				flowExtract.temp_encrypted_content = encrypt_OpenSSL(&ctx, flowExtract.temp_file_content, flowExtract.offset_array[counter], &i);
			}
			memcpy(flowExtract.encrypted_file_content + offset, flowExtract.temp_encrypted_content, flowExtract.offset_array[counter]);
			offset = offset + flowExtract.offset_array[counter];
			//printf("%x %x\n", temp_read[0], temp_read[1]);
			counter++;
		}
		//free(flow_extract.temp_encrypted_content);
		//free(flow_extract.temp_file_content);
		fclose(flowExtract.fp_content);
	}
	flowExtract.current_offset = 0;
	//printf("line: %d\n", __LINE__);

	libtrace_out_t *writer = 0;
	// Open traces and write the encrypted data back to trace.
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

	//printf("line: %d\n", __LINE__);
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

	for (;;) {
		psize = trace_read_packet(trace, pkt);
		if (psize == 0) {
			break;
		}
		if (psize < 0) {
			trace_perror(trace, "read_packet");
			break;
		}
		if ((per_packet_overwrite(pkt, writer, flowExtract.encrypted_file_content, &traceOffset, &flowExtract)) == -1)
		{
			fprintf(stderr, "Something went wrong in per_packet.\n");
			break;
		}
		pktCount++;
	}

	trace_destroy_packet(pkt);
	trace_destroy(trace);
	trace_destroy_output(writer);
	//printf("line: %d\n", __LINE__);

	time(&end);
	double cost = difftime(end, start);
	//printf("running time: %f\n", cost);

	if(enableEncryption == 1)
	{
		//free(flow_extract.file_content);
		if( strcmp(encryptionAlgorithm, "xor") == 0 )
		{
			//free(flow_extract.encrypted_file_content);
		}
	}
	//free(flow_extract.encrypted_file_content);
	//free(flow_extract.offset_array);
	//free(key);
	//free(iv);

	return 0;
}
