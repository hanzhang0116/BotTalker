/*
Encrypt individual packet's payload
1. The encrypted payload size doesn't change: XOR, CFB, OFB
	Encrypt payload and put the encrypted payload back to packet
2. The encrypted payload size changes: ECB, CBC
	Step1: Encrypt payload
	Step2: Trim the encrypted payload as the same size of original payload size
	Step3: Put trimmed encrypted payload back to packet
3. Deal with GET/POST request in packet
	Search for "\d\r\d\r", the string after that is the payload need to encrypt

Note:
	With IP replacement and GET/POST request parser
	IP replacement is not the latest version, code ConvertSSHTrace.c has the latest one
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

#define MAX_SIZE 1024

struct time_adjust_record
{
	char src_ip[16];
	int src_port;
	char dest_ip[16];
	int dest_port;
	int rtt_sec;
	int rtt_usec;
	int client_inter_sec;
	int client_inter_usec;
	int server_inter_sec;
	int server_inter_usec;
	int reaction_sec;
	int reaction_usec;
	int first_pkt_sec;
	int first_pkt_usec;
	int last_tv_sec;
	int last_tv_usec;
	int last_direction;
};

int Set_Time_Adjust(char * buffer, int * i, int * j)
{
	char * p = NULL;
	p = strtok(buffer, ".");
	if(p)
	{
		*i = atoi(p);
	}
	else
	{
		printf("Miss some number in time adjust file\n");
		return 1;
	}
	p = strtok(NULL, ".");
	if(p)
	{
		*j = atoi(p);
	}
	else
	{
		printf("Miss some number time adjust file\n");
		return 1;
	}
	return 0;
}



static int per_packet(libtrace_packet_t * pkt, FILE * fp_write, struct time_adjust_record * time_adjust_flow)
{

	// Create a new packet which is a copy of the old packet.
	//libtrace_packet_t *copy_pkt = trace_copy_packet(pkt);
	libtrace_ip_t *ip = trace_get_ip(pkt);
	libtrace_ip6_t *ip6 = trace_get_ip6(pkt);

	struct sockaddr_storage src_addr;
	struct sockaddr_storage dest_addr;
	struct sockaddr *src_addr_ptr;
	struct sockaddr *dest_addr_ptr;
	/* L3 data */
	void *l3;
	uint16_t ethertype;
	/* Transport data */
	void *transport;
	uint8_t proto;
	/* Payload data */
	uint32_t remaining;

	struct timeval ts;

	//printf("In per_packet line:%d\n", __LINE__);

	l3 = trace_get_layer3(pkt,&ethertype,&remaining);

	if (!l3)
	{
		/* Probable ARP or something */
		return;
	}

	/* Get the UDP/TCP/ICMP header from the IPv4/IPv6 packet */
	/*switch (ethertype) {
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
	}*/

	// Get packet information
	//get port numbers
	int src_port = trace_get_source_port(pkt);
	int dest_port = trace_get_destination_port(pkt);
	src_addr_ptr = trace_get_source_address(pkt, (struct sockaddr *) &src_addr);
	dest_addr_ptr = trace_get_destination_address(pkt, (struct sockaddr *) &dest_addr);
	if( (NULL == src_addr_ptr) || (NULL == dest_addr_ptr) )
	{
		//printf("In per_packet line:%d\n", __LINE__);
		return;
	}
	//get source ip address
	char src_ip[100];
	if (src_addr_ptr->sa_family == AF_INET) {
		struct sockaddr_in *src_v4 = (struct sockaddr_in *) src_addr_ptr;
		inet_ntop(AF_INET, &(src_v4->sin_addr), src_ip, 100);
	}
	//get destination ip address
	char dest_ip[100];
	if (dest_addr_ptr->sa_family == AF_INET) {
		struct sockaddr_in *dest_v4 = (struct sockaddr_in *) dest_addr_ptr;
		inet_ntop(AF_INET, &(dest_v4->sin_addr), dest_ip, 100);
	}

	ts = trace_get_timeval(pkt);
	struct timeval ts_adjust;
	ts_adjust.tv_sec = 0;
	ts_adjust.tv_usec = 0;


	//printf("1 %s %d %s %d\n", time_adjust_flow->src_ip, time_adjust_flow->src_port, time_adjust_flow->dest_ip, time_adjust_flow->dest_port);
	//printf("2 %s %d %s %d\n", src_ip, src_port, dest_ip, dest_port);
	if( (src_port == time_adjust_flow->src_port) && (strcmp(src_ip, time_adjust_flow->src_ip) == 0) && (dest_port == time_adjust_flow->dest_port) && (strcmp(dest_ip, time_adjust_flow->dest_ip) == 0) ) 
	{
		//printf("CASE1: in per_packet line:%d\n", __LINE__);
		if(time_adjust_flow->last_direction == -1)
		{
			time_adjust_flow->last_direction = 0;
			ts_adjust.tv_sec = time_adjust_flow->first_pkt_sec;
			ts_adjust.tv_usec = time_adjust_flow->first_pkt_usec;
		}
		else if(time_adjust_flow->last_direction == 0)	//update rtt
		{
			//add client inter arrival time
			if(time_adjust_flow->client_inter_usec + time_adjust_flow->last_tv_usec >= 1000000)
			{
				ts_adjust.tv_usec = time_adjust_flow->client_inter_usec + time_adjust_flow->last_tv_usec - 1000000;
				ts_adjust.tv_sec = time_adjust_flow->client_inter_sec + time_adjust_flow->last_tv_sec + 1;
			}
			else
			{
				ts_adjust.tv_sec = time_adjust_flow->client_inter_sec + time_adjust_flow->last_tv_sec;
				ts_adjust.tv_usec = time_adjust_flow->client_inter_usec + time_adjust_flow->last_tv_usec;
			}
		}
		else if(time_adjust_flow->last_direction == 1)
		{
			//add reaction time
			if(time_adjust_flow->reaction_usec + time_adjust_flow->last_tv_usec >= 1000000)
			{
				ts_adjust.tv_usec = time_adjust_flow->reaction_usec + time_adjust_flow->last_tv_usec - 1000000;
				ts_adjust.tv_sec = time_adjust_flow->reaction_sec + time_adjust_flow->last_tv_sec + 1;
			}
			else
			{
				ts_adjust.tv_usec = time_adjust_flow->reaction_usec + time_adjust_flow->last_tv_usec;
				ts_adjust.tv_sec = time_adjust_flow->reaction_sec + time_adjust_flow->last_tv_sec;
			}
			time_adjust_flow->last_direction = 0;
		}
		time_adjust_flow->last_tv_sec = ts_adjust.tv_sec;
		time_adjust_flow->last_tv_usec = ts_adjust.tv_usec;
		fprintf(fp_write, "%d, %d\n", time_adjust_flow->last_tv_sec, time_adjust_flow->last_tv_usec);
		//printf("%d, %d\n", time_adjust_flow->last_tv_sec, time_adjust_flow->last_tv_usec);
	}
	if( (src_port == time_adjust_flow->dest_port) && (strcmp(src_ip, time_adjust_flow->dest_ip) == 0) && (dest_port == time_adjust_flow->src_port) && (strcmp(dest_ip, time_adjust_flow->src_ip) == 0) ) 
	{
		//printf("CASE2 in per_packet line:%d\n", __LINE__);
		if(time_adjust_flow->last_direction == -1)
		{
			time_adjust_flow->last_direction = 1;
			ts_adjust.tv_sec = time_adjust_flow->first_pkt_sec;
			ts_adjust.tv_usec = time_adjust_flow->first_pkt_usec;
		}
		else if(time_adjust_flow->last_direction == 1)	//update rtt
		{
			//add server inter arrival time
			if(time_adjust_flow->server_inter_usec + time_adjust_flow->last_tv_usec >= 1000000)
			{
				ts_adjust.tv_usec = time_adjust_flow->server_inter_usec + time_adjust_flow->last_tv_usec - 1000000;
				ts_adjust.tv_sec = time_adjust_flow->server_inter_sec + time_adjust_flow->last_tv_sec + 1;
			}
			else
			{
				ts_adjust.tv_usec = time_adjust_flow->server_inter_usec + time_adjust_flow->last_tv_usec;
				ts_adjust.tv_sec = time_adjust_flow->server_inter_sec + time_adjust_flow->last_tv_sec;
			}
			//printf("Pkt: %d, last_tv_sec: %d last_tv_usec: %d, ts.tv_sec: %u, ts.tv_usec: %u, rtt_avg_direct0: %f\n", flow_stats.pkt_count, flow_stats.last_tv_sec, flow_stats.last_tv_usec, ts.tv_sec, ts.tv_usec, flow_stats.rtt_avg_direct1);
		}
		else if(time_adjust_flow->last_direction == 0)
		{
			// add client RTT
			if(time_adjust_flow->rtt_usec + time_adjust_flow->last_tv_usec >= 1000000)
			{
				ts_adjust.tv_usec = time_adjust_flow->rtt_usec + time_adjust_flow->last_tv_usec - 1000000;
				ts_adjust.tv_sec = time_adjust_flow->rtt_sec + time_adjust_flow->last_tv_sec + 1;
			}
			else
			{
				ts_adjust.tv_sec = time_adjust_flow->rtt_sec + time_adjust_flow->last_tv_sec;
				ts_adjust.tv_usec = time_adjust_flow->rtt_usec + time_adjust_flow->last_tv_usec;
			}
			time_adjust_flow->last_direction = 1;
		}
		time_adjust_flow->last_tv_sec = ts_adjust.tv_sec;
		time_adjust_flow->last_tv_usec = ts_adjust.tv_usec;
		fprintf(fp_write, "%d, %d\n", time_adjust_flow->last_tv_sec, time_adjust_flow->last_tv_usec);
		//printf("%d, %d\n", time_adjust_flow->last_tv_sec, time_adjust_flow->last_tv_usec);
	}

	//trace_destroy_packet(copy_pkt);
	return 0;

	/*if ( (strcmp(src_ip, "")) || (strcmp(dest_ip, "")) )
	  {
  sprintf(OutputBuffer, "sec: %u, usec: %u, src_ip: %s, src_port: %d, dest_ip: %s, dest_port: %d, pkt_size: %d, remaining: %d", ts.tv_sec, ts.tv_usec, src_ip, src_port, dest_ip, dest_port, pkt_size, remaining);
  }*/

}

int main(int argc, char *argv[])
{
	clock_t start;
	clock_t end;
	double function_time;

	struct time_adjust_record time_adjust_flow1 = {"0.0.0.0", 0, "0.0.0.0", 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, -1};
	char * p = NULL;
	FILE * fp_time_adjust = NULL;
	FILE * fp_write = NULL;
	char time_adjust_file[128];
	char file_write[256];
	char input_file[256];
	char buffer[256];

	if (argc < 4)
	{
		printf("Please enter two parameters: read_file and write_file\n");
		return 1;
	}

	strcpy(input_file, argv[1]);
	strcpy(time_adjust_file, argv[2]);
	strcpy(file_write, argv[3]);

	if((fp_time_adjust = fopen(time_adjust_file, "r")) == NULL)  //open the file to read
	{
		fprintf(stderr, "Open time adjust file: %s failed\n", time_adjust_file);
		exit(1);
	}
	memset(buffer, '\0', sizeof(buffer));
	fgets(buffer, sizeof(buffer), fp_time_adjust);
	p = strtok(buffer, " ");
	if(p)
	{
		strcpy( time_adjust_flow1.src_ip, p);
	}
	p = strtok(NULL, " ");
	if(p)
	{
		time_adjust_flow1.src_port = atoi(p);
	}
	p = strtok(NULL, " ");
	if(p)
	{
		strcpy( time_adjust_flow1.dest_ip, p);
	}
	p = strtok(NULL, " ");
	if(p)
	{
		time_adjust_flow1.dest_port = atoi(p);
	}
	//printf("flow: %s:%d %s:%d\n", time_adjust_flow1.src_ip, time_adjust_flow1.src_port, time_adjust_flow1.dest_ip, time_adjust_flow1.dest_port);
	memset(buffer, '\0', sizeof(buffer));
	fgets(buffer, sizeof(buffer), fp_time_adjust);
	if( Set_Time_Adjust(buffer, &time_adjust_flow1.first_pkt_sec, &time_adjust_flow1.first_pkt_usec) != 0 )
	{
		printf("line: %d\n", __LINE__);
		exit(1);
	}
	//printf("First packet second: %d, usecond: %d\n", time_adjust_flow1.first_pkt_sec, time_adjust_flow1.first_pkt_usec);
	memset(buffer, '\0', sizeof(buffer));
	fgets(buffer, sizeof(buffer), fp_time_adjust);
	if( Set_Time_Adjust(buffer, &time_adjust_flow1.client_inter_sec, &time_adjust_flow1.client_inter_usec) != 0 )
	{
		printf("line: %d\n", __LINE__);
		exit(1);
	}
	//printf("Client packet inter arrival second: %d, usecond: %d\n", time_adjust_flow1.client_inter_sec, time_adjust_flow1.client_inter_usec);
	memset(buffer, '\0', sizeof(buffer));
	fgets(buffer, sizeof(buffer), fp_time_adjust);
	if( Set_Time_Adjust(buffer, &time_adjust_flow1.server_inter_sec, &time_adjust_flow1.server_inter_usec) != 0 )
	{
		printf("line: %d\n", __LINE__);
		exit(1);
	}
	//printf("Server packet inter arrival second: %d, usecond: %d\n", time_adjust_flow1.server_inter_sec, time_adjust_flow1.server_inter_usec);
	memset(buffer, '\0', sizeof(buffer));
	fgets(buffer, sizeof(buffer), fp_time_adjust);
	if( Set_Time_Adjust(buffer, &time_adjust_flow1.reaction_sec, &time_adjust_flow1.reaction_usec) != 0 )
	{
		printf("line: %d\n", __LINE__);
		exit(1);
	}
	//printf("Client reaction second: %d, usecond: %d\n", time_adjust_flow1.reaction_sec, time_adjust_flow1.reaction_usec);
	memset(buffer, '\0', sizeof(buffer));
	fgets(buffer, sizeof(buffer), fp_time_adjust);
	if( Set_Time_Adjust(buffer, &time_adjust_flow1.rtt_sec, &time_adjust_flow1.rtt_usec) != 0 )
	{
		printf("line: %d\n", __LINE__);
		exit(1);
	}
	//time_adjust_flow1.rtt_usec = time_adjust_flow1.rtt_sec*1000 + time_adjust_flow1.rtt_usec*1000;
	//time_adjust_flow1.rtt_sec = time_adjust_flow1.rtt_sec/1000;
	//printf("Client RTT second: %d, usecond: %d\n", time_adjust_flow1.rtt_sec, time_adjust_flow1.rtt_usec);
	fclose(fp_time_adjust);
	
	if((fp_write=fopen(file_write, "w")) == NULL)  //open the file to read
        {
                fprintf(stderr, "Open write file: %s failed\n", file_write);
                exit(1);
        }

	libtrace_t *trace = 0;
	libtrace_out_t *writer = 0;
	libtrace_packet_t *pkt = trace_create_packet();

	// Open traces for reading and writing.
	trace = trace_create(input_file);
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

	//char output_file[] = "pcap:ttt.pcap";
	//writer = trace_create_output("pcap:testcp");
	/*writer = trace_create_output(output_file);
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
	}*/

	int psize = 0;
	int pkt_count = 0;
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
			//printf("packet: %d\n", pkt_count);
			if ((per_packet(pkt, fp_write, &time_adjust_flow1)) == -1)
			{
				fprintf(stderr, "Something went wrong in per_packet.\n");
				break;
			}
		}
		pkt_count++;
	}

	trace_destroy_packet(pkt);
	trace_destroy(trace);
	//trace_destroy_output(writer);
	fclose(fp_write);

	return 0;
}
