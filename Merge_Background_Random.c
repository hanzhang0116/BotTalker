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

int localSubnet = 32;
int botnetSubnet = 32;
int localIPNum = 0;
int botnetIPNum = 0;
int enableReplaceIP = 0;		//apply IP replacement
char localIP[16];		//original IP
char botnetIP[16];		//new IP 
struct flow_record flowExtract;
struct ip_list * localIPHead = NULL;
struct ip_list * localIPLast = NULL;
struct ip_list * botnetIPHead = NULL;
struct ip_list * botnetIPLast = NULL;
struct ip_pair * localBotnetPairsHead = NULL;
struct ip_pair * localBotnetPairsLast = NULL;
//struct flow_rtt_inter flow_stats = {0, "129.82.138.45", 52424, "129.82.138.36", 60000, 0, 0, -1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};


static int per_packet(libtrace_packet_t * pkt, libtrace_out_t * wr, int list)
{
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

	int i = 0;
	int ipMatch = -1;
	int pktSize;
	char srcIP[100];
	char destIP[100];

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

	pktSize = trace_get_capture_length(copyPkt);

	struct ip_list * ipIterate;
	if(list == 0)
	{
		ipIterate = localIPHead;
	}
	else if(list == 1)
	{
		ipIterate = botnetIPHead;
	}
	if((list == 0) || (list == 1))
	{
		if(list == 0)
		{
			if(IPBelongTo(localIP, srcIP, localSubnet) == 0)
			{
				ipMatch = 0;
			}
			else if( IPBelongTo(localIP, destIP, localSubnet) == 0)
			{
				ipMatch = 1;
			}
			else
			{
				ipMatch = -1;
				return;
			}
		}
		else if(list == 1)
		{
			if(IPBelongTo(botnetIP, srcIP, botnetSubnet) == 0)
			{
				ipMatch = 0;
			}
			else if( IPBelongTo(botnetIP, destIP, botnetSubnet) == 0)
			{
				ipMatch = 1;
			}
			else
			{
				ipMatch = -1;
				return;
			}
		}
		//the first ip
		if(ipIterate == NULL)
		{
			struct ip_list * new = (struct ip_list *)malloc(sizeof(struct ip_list));
			if(ipMatch == 0)
			{
				strcpy(new->ip, srcIP);
			}
			else if(ipMatch == 1)
			{
				strcpy(new->ip, destIP);
			}
			new->next = NULL;
			new->paired = -1;
			if(list == 0)
			{
				localIPHead = new;
				localIPLast = new;
				localIPNum++;
			}
			else if(list == 1)
			{	
				botnetIPHead = new;
				botnetIPLast = new;
				botnetIPNum++;
			}
			//printf("Add Head: %s\n", new->ip);
		}
		else
		{
			while(ipIterate)
			{
				if(ipMatch == 0)
				{
					if( strcmp(ipIterate->ip, srcIP) == 0)
					{
						return;
					}
				}
				else if(ipMatch == 1)
				{
					if( strcmp(ipIterate->ip, destIP) == 0)
					{
						return;
					}
				}
				ipIterate = ipIterate->next;
			}
			struct ip_list * new = (struct ip_list *)malloc(sizeof(struct ip_list));
			new->next = NULL;
			new->paired = -1;
			if(ipMatch == 0)
			{
				strcpy(new->ip, srcIP);
			}
			else if(ipMatch == 1)
			{
				strcpy(new->ip, destIP);
			}
			if(list == 0)
			{
				localIPLast->next = new;
				localIPLast = new;
				localIPNum++;
			}
			else if(list == 1)
			{
				botnetIPLast->next = new;
				botnetIPLast = new;
				botnetIPNum++;
			}
			//printf("Add: %s\n", new->ip);
		}
	}
	else
	{
		struct ip_pair * pairIterate =  localBotnetPairsHead;
		while(pairIterate)
		{
			if( (strcmp(srcIP, pairIterate->ip1) == 0) || (strcmp(destIP, pairIterate->ip1) == 0) )
			{
				//printf("line: %d\n", __LINE__);
				ReplaceIP(ip, pairIterate->ip1, pairIterate->ip2, 32, 0);
				ReplaceIP(ip, pairIterate->ip1, pairIterate->ip2, 32, 1);
				//break;
			}
			pairIterate = pairIterate->next;
		}

		if (trace_write_packet(wr, copyPkt) == -1)
		{
			trace_perror_output(wr, "Writing packet");
			return -1;
		}
	}
	trace_destroy_packet(copyPkt);
	return 0;

}

int main(int argc, char *argv[])
{
	char * p = NULL;
	clock_t start;
	clock_t end;
	double cost;
	int opt = 0;
	int psize = 0;
	int pktCount = 0;
	char bufferTemp[MAX_SIZE];
	char inputFile[MAX_SIZE];
	char outputFile[MAX_SIZE];
	char botnetIPSubnet[MAX_SIZE];
	char backgroundFile[MAX_SIZE];

	if ((argc - optind) < 1) {
		usage();
		exit(1);
	}

	while ((opt = getopt(argc, argv, "b:l:i:o:M:")) !=-1)
	{
		switch (opt)
		{
			case 'i':
				strcpy(inputFile, optarg);
				break;
			case 'o':
				strcpy(outputFile, optarg);
				break;
			case 'b':
				strcpy(backgroundFile, optarg);
				break;
			case 'l':
				p = NULL;
				strcpy(bufferTemp, optarg);
				p = strtok(bufferTemp, "/");
				if(p)
				{
					strcpy(localIP, p);
				}
				p = strtok(NULL, "/");
				if(p)
				{
					localSubnet = atoi(p);
				}
				printf("local_ip: %s, local_subnet: %d\n", localIP, localSubnet);
				break;
			case 'M':
				p = NULL;
				strcpy(bufferTemp, optarg);
				p = strtok(bufferTemp, "/");
				if(p)
				{
					strcpy(botnetIP, p);
				}
				p = strtok(NULL, "/");
				if(p)
				{
					botnetSubnet = atoi(p);
				}
				printf("botnet_ip: %s, botnet_subnet: %d\n", botnetIP, botnetSubnet);
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
	for (;;) {
		psize = trace_read_packet(trace, pkt);
		if (psize == 0) {
			break;
		}
		if (psize < 0) {
			trace_perror(trace, "read_packet");
			break;
		}
		if ((per_packet(pkt, writer, 1)) == -1)
		{
			fprintf(stderr, "Something went wrong in per_packet.\n");
			break;
		}
	}
	//trace_destroy(trace);

	// Open background traces for reading and writing.
	trace = trace_create(backgroundFile);
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
		if ((per_packet(pkt, writer, 0)) == -1)
		{
			fprintf(stderr, "Something went wrong in per_packet.\n");
			break;
		}
	}
	//trace_destroy(trace);

	struct ip_list * ipIterate = localIPHead;

	int i = 0;
	int j = 0;
	int loop = 0;
	int tempLocalIPNum = localIPNum;
	for(i=0; i<botnetIPNum; i++)
	{
		struct ip_pair * newPair = (struct ip_pair *)malloc(sizeof(struct ip_pair));
		loop = 0;
		ipIterate = botnetIPHead;
		while(ipIterate)
		{
			if(loop==i)
			{
				strcpy(newPair->ip1, ipIterate->ip);
				break;
			}
			loop++;
			ipIterate = ipIterate->next;
		}
		srand ( time(NULL) );
		j = rand()%tempLocalIPNum;
		printf("local hosts: %d\n", localIPNum);
		printf("random: %d\n", j);
		tempLocalIPNum--;
		loop = 0;
		ipIterate = localIPHead;
		while(ipIterate)
		{
			if(loop == j)
			{
				if(ipIterate->paired == -1)
				{
					strcpy(newPair->ip2, ipIterate->ip);
					newPair->next = NULL;
					ipIterate->paired = 1;
					break;
				}
				loop--;
			}
			loop++;
			ipIterate = ipIterate->next;
		}
		if(localBotnetPairsHead == NULL)
		{
			localBotnetPairsHead = newPair;
			localBotnetPairsLast = newPair;
		}
		else
		{
			localBotnetPairsLast->next = newPair;
			localBotnetPairsLast = newPair;
		}
	}

	struct ip_pair * pairIterate =  localBotnetPairsHead;
	while(pairIterate)
	{
		printf("botnet ip: %s <-> local ip: %s\n", pairIterate->ip1, pairIterate->ip2);
		pairIterate = pairIterate->next;
	}

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
	for (;;) {
		psize = trace_read_packet(trace, pkt);
		if (psize == 0) {
			break;
		}
		if (psize < 0) {
			trace_perror(trace, "read_packet");
			break;
		}
		if ((per_packet(pkt, writer, -1)) == -1)
		{
			fprintf(stderr, "Something went wrong in per_packet.\n");
			break;
		}
	}

	//encrypt traffic and write to new file

	trace_destroy_packet(pkt);
	trace_destroy(trace);
	trace_destroy_output(writer);

	time(&end);
	cost = difftime(end, start);
	printf("running time: %f\n", cost);

	return 0;
}
