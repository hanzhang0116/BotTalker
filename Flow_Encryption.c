
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

int enableIPAnonymize = 0;	//1 means the ip needs to be anonymized
int enablePortFilter = 0;	//1 means the port needs to be filtered
int enableEncryption = 0;		//1 means the data needs to be encrypted
int enableKeyIV = 0;
int encryptAll = 0;		//encrypt all the traffic, otherwise encrypt a specific flow
int enableEncryptExecutable = 0;	//1 means use the executable magic number files
int enableReplaceIP = 0;		//apply IP replacement
char oriIP[16];		//original IP
char replaceIP[16];		//new IP 
char encryptionAlgorithm[32];	//specify the encryption algorithm
//struct flow_record flow_extract;
extern struct flow_record * flowExtractHead;
extern struct flow_record * flowExtractLast;
extern struct port_list * portExclusion;

static int per_packet_extract_flow_records(libtrace_packet_t * pkt, FILE * fpOut)
{
	// Create a new packet which is a copy of the old packet.
	//libtrace_packet_t *copy_pkt = trace_copy_packet(pkt);
	libtrace_ip_t *ip = trace_get_ip(pkt);
	libtrace_ip6_t *ip6 = trace_get_ip6(pkt);

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
	if( (CheckExclusionPort(srcPort)==1) || (CheckExclusionPort(destPort)==1) )
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

	if(proto == 17)	//udp
	{
		payload = trace_get_payload_from_udp( (libtrace_udp_t*)transport, &remaining);
	}

	if(proto == 6)	//tcp
	{
		payload = trace_get_payload_from_tcp( (libtrace_tcp_t*)transport, &remaining);
	}
	if(remaining <= 0)
	{
		return;
	}
	iteFlowRecord = flowExtractHead;
	while(iteFlowRecord)
	{
		if( ( (proto == iteFlowRecord->proto) && (srcPort == iteFlowRecord->src_port) && (strcmp(srcIP, iteFlowRecord->src_ip) == 0) && (destPort == iteFlowRecord->dest_port) && (strcmp(destIP, iteFlowRecord->dest_ip) == 0) ) || ( (destPort == iteFlowRecord->src_port) && (strcmp(destIP, iteFlowRecord->src_ip) == 0) && (srcPort == iteFlowRecord->dest_port) && (strcmp(srcIP, iteFlowRecord->dest_ip) == 0) && (proto == iteFlowRecord->proto) ) )
		{
			break;
		}
		iteFlowRecord = iteFlowRecord->next;
	}
	if(iteFlowRecord == NULL)
	{
		struct flow_record * newFlowRecord = (struct flow_record *)malloc(sizeof(struct flow_record));
		strcpy(newFlowRecord->src_ip, srcIP);
		newFlowRecord->src_port = srcPort;
		strcpy(newFlowRecord->dest_ip, destIP);
		newFlowRecord->dest_port = destPort;
		newFlowRecord->proto = proto;
		newFlowRecord->next = NULL;
		if(flowExtractHead == NULL)
		{
			//printf("line: %d\n", __LINE__);
			flowExtractHead = newFlowRecord;
			//debug
			/*if(flowExtractHead == NULL)
			{
				printf("line: %d\n", __LINE__);
			}*/
		}
		else
		{
			flowExtractLast->next = newFlowRecord;
		}
		flowExtractLast = newFlowRecord;
		fprintf(fpOut, "%s %d %s %d %d\n", newFlowRecord->src_ip, newFlowRecord->src_port, newFlowRecord->dest_ip, newFlowRecord->dest_port, newFlowRecord->proto);
		//printf("%s %d %s %d %d\n", newFlowRecord->src_ip, newFlowRecord->src_port, newFlowRecord->dest_ip, newFlowRecord->dest_port, newFlowRecord->proto);
	}
}

static int extract_flow_records(char * flowRecordsFile, char * inputFile)
{
	FILE * fpOut = NULL;
	int psize = 0;
	struct flow_record * flowRecordsHead;
	libtrace_t *trace = 0;
	libtrace_packet_t *pkt = trace_create_packet();
	if((fpOut = fopen(flowRecordsFile, "w+")) == NULL)  //open the file to read
	{
		fprintf(stderr, "Open file: %s failed\n", flowRecordsFile);
		exit(1);
	}
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
		if ((per_packet_extract_flow_records(pkt, fpOut)) == -1)
		{
			fprintf(stderr, "Something went wrong in per_packet.\n");
			break;
		}
		//debug
		/*
		if(flowExtractHead == NULL)
		{
			printf("line: %d\n", __LINE__);
		}
		*/
	}
	fclose(fpOut);
}

int main(int argc, char *argv[])
{
	char * p = NULL;
	//char * file_content = NULL;
	//char * encrypted_file_content;
	struct flow_record * iteFlowRecord;
	int i = 0;
	int opt = 0;
	int psize = 0;
	int pktCount = 0;
	int offset = 0;
	int filesize = 0;
	int readLength = 0;
	int traceOffset = 0;
	int oriSubnet = 0;
	int replaceSubnet = 0;
	int enableReplaceCertainIP = 0;
	int enableReplaceAllIP = 0;
	int enableIPExclusion = 0;
	int enablePortExclusion = 0;
	char tempRead[100];
	char inputFile[MAX_SIZE];
	char outputFile[MAX_SIZE];
	char flowsFile[MAX_SIZE];
	char keyIVFile[MAX_SIZE];
	char oriReplaceIP[MAX_SIZE];
	char bufferTemp[MAX_SIZE];
	char encryptionAlgorithm[MAX_SIZE];
	char portExclusionFile[MAX_SIZE];
	char ipExclusionFile[MAX_SIZE];
	char command[MAX_SIZE];
	char inputFileTemp[MAX_SIZE];
	char outputFileTemp[MAX_SIZE];
	clock_t start;
	clock_t end;
	double functionTime;

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
				break;
			case 'f':
				/*encrypt all the traffic*/
				if(strcmp("all", optarg) == 0)
				{
					encryptAll = 1;
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

	if(enablePortExclusion == 1)
	{
		ReadPortExclusionRecords(portExclusionFile);
	}

	if(enableEncryption == 1)
	{
		if(encryptAll == 1)
		{
			memset(flowsFile, '\0', sizeof(flowsFile));
			sprintf(flowsFile, "%s-flows", inputFile);
			extract_flow_records(flowsFile, inputFile);
		}
		else
		{
			ReadFlowRecords(flowsFile);
		}
		//write the flow payload to file
		strcpy(inputFileTemp, inputFile);
		iteFlowRecord = flowExtractHead;
		while(iteFlowRecord)
		{
			memset(outputFileTemp, '\0', sizeof(outputFileTemp));
			memset(command, '\0', sizeof(command));
			sprintf(outputFileTemp, "temp-trace-%s-%d-%s-%d-%d", iteFlowRecord->src_ip, iteFlowRecord->src_port, iteFlowRecord->dest_ip, iteFlowRecord->dest_port, iteFlowRecord->proto);
			sprintf(command, "./Flow_Encryption_SingleFlow -i pcap:%s -o pcap:%s -k %s -e %s -f '%s %d %s %d %d'", inputFileTemp, outputFileTemp, keyIVFile, encryptionAlgorithm, iteFlowRecord->src_ip, iteFlowRecord->src_port, iteFlowRecord->dest_ip, iteFlowRecord->dest_port, iteFlowRecord->proto);
			printf("%s\n", command);
			system(command);
			memset(inputFileTemp, '\0', sizeof(inputFileTemp));
			strcpy(inputFileTemp, outputFileTemp);
			iteFlowRecord = iteFlowRecord->next;
		}
		if(enableReplaceIP == 1)
		{
			memset(command, '\0', sizeof(command));
			sprintf(command, "./Flow_Encryption_SingleFlow -i pcap:%s -o pcap:%s -r '%s'", outputFileTemp, outputFile, oriReplaceIP);
			if(enableReplaceCertainIP == 1)
			{
				sprintf(command, "%s -n", command);
			}
			if(enableReplaceAllIP == 1)
			{
				sprintf(command, "%s -N", command);
			}
			printf("%s\n", command);
			system(command);
		}
		else
		{
			memset(command, '\0', sizeof(command));
			sprintf(command, "mv %s %s", outputFileTemp, outputFile);
			system(command);
			printf("%s\n", command);
		}
	}
	else if(enableReplaceIP == 1)
	{
		memset(command, '\0', sizeof(command));
		sprintf(command, "./Flow_Encryption_SingleFlow -i pcap:%s -o pcap:%s -r '%s'", inputFile, outputFile, oriReplaceIP);
		system(command);
		printf("%s\n", command);
	}
	memset(command, '\0', sizeof(command));
	sprintf(command, "rm temp-trace-*");
	system(command);
	memset(command, '\0', sizeof(command));
	sprintf(command, "rm *-flow-offset");
	system(command);
	memset(command, '\0', sizeof(command));
	sprintf(command, "rm *-flow-payload");
	system(command);

	time(&end);
	double cost = difftime(end, start);
	printf("running time: %f\n", cost);

	return 0;
}
