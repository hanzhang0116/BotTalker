
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

#define MAX_SIZE 1024
#define FILENAME_LENGTH 1024
#define CADIR NULL

/*reserved for SSL emulation*/
//char passwd[] = "";

struct flow_record * flowExtractHead = NULL;
struct flow_record * flowExtractLast = NULL;
struct ip_list * ipExclusion = NULL;
struct port_list * portExclusion = NULL;

struct config_parameters
{
	char COMMAND_EDITCAP[MAX_SIZE];
	char COMMAND_MERGECAP[MAX_SIZE];
	char CIPHER_LIST[MAX_SIZE];
	char CAFILE[MAX_SIZE];
	char CERTFILE[MAX_SIZE];
	char SERVER[MAX_SIZE];
	char CLIENT[MAX_SIZE];
	char PORT[MAX_SIZE];
	char ETH[MAX_SIZE];
};

struct port_list
{
	int port;
	struct port_list * next;
};

struct ip_list
{
	char ip[16];
	int paired;
	struct ip_list * next;
};

struct ip_pair
{
	char ip1[16];
	char ip2[16];
	struct ip_pair * next;
};

struct flow_offset
{
	int offset;
	struct flow_offset * next;
};

struct flow_record
{
	char src_ip[16];
	int src_port;
	char dest_ip[16];
	int dest_port;
	int proto;
	FILE * fp_content;
	FILE * fp_offset;
	char flow_offset_file[MAX_SIZE];
	char flow_payload_file[MAX_SIZE];
	int current_offset;
	int last_direction;
	int offset_count;
	int flow_size;
	int offset_max;
	int * offset_array;
	char * file_content;
	char * encrypted_file_content;
	char * temp_file_content;
	char * temp_encrypted_content;
	struct flow_record * next;
};

struct flow_rtt_inter	//used in calculation of rtt
{
	//direct0 stands for client to server
	int pkt_count;
	char src_ip[16];
	int src_port;
	char dest_ip[16];
	int dest_port;
	int proto;
	int last_tv_sec;
	int last_tv_usec;
	int last_direction;
	float rtt_avg_direct0;
	int rtt_count_direct0;
	float inter_avg_direct0;
	int inter_count_direct0;
	float rtt_avg_direct1;
	int rtt_count_direct1;
	float inter_avg_direct1;
	int inter_count_direct1;
	float reaction_avg_direct0;
	int reaction_count_direct0;
};


struct struct_IPReplace
{
	char original_IP[16];
	char replace_IP[16];
	int subnet;
};

int substring(char * string, char * substring)
{
	char *a, *b;
	int offset = 0;

	b = substring;
	if (*b == 0) {
		return -1;
	}
	for ( ; *string != 0; string += 1) {
		offset++;
		if (*string != *b) {
			continue;
		}
		a = string;
		while (1) {
			if (*b == 0) {
				return offset-1;
			}
			if (*a++ != *b++) {
				break;
			}
		}
		b = substring;
	}
	return -1;
}

int ReadConfigurationFile(char * configFile, struct config_parameters * configBottalker )
{
	FILE * fpRead = NULL;
	char buffer[MAX_SIZE];
	char temp[MAX_SIZE];
	char * p = NULL;
	if((fpRead = fopen(configFile, "r")) == NULL)  //open the file     to read
	{
		fprintf(stderr, "Line %d: Open file: configuration file %s failed\n", __LINE__, configFile);
		exit(1);
	}
	while(!feof(fpRead))
	{
		fgets(buffer, sizeof(buffer), fpRead);
		memset(temp, '\0', sizeof(temp));
		strcpy(temp, buffer);
		if(feof(fpRead))
		{
			break;
		}
		p = strtok(buffer, "=");
		p = strtok(NULL, "\n");
		if( substring(temp, "MERGECAP") >= 0)
		{
			strcpy(configBottalker->COMMAND_MERGECAP, p);
		}
		else if( substring(temp, "EDITCAP") >= 0)
		{
			strcpy(configBottalker->COMMAND_EDITCAP, p);
		}
		else if( substring(temp, "CIPHER_LIST") >= 0)
		{
			strcpy(configBottalker->CIPHER_LIST, p);
		}
		else if( substring(temp, "CAFILE") >= 0)
		{
			strcpy(configBottalker->CAFILE, p);
		}
		else if( substring(temp, "CERTFILE") >= 0)
		{
			strcpy(configBottalker->CERTFILE, p);
		}
		else if( substring(temp, "PORT") >= 0)
		{
			strcpy( configBottalker->PORT, p);
		}
		else if( substring(temp, "ETH") >= 0)
		{
			strcpy( configBottalker->ETH, p);
		}
		else if( substring(temp, "SERVER") >= 0)
		{
			strcpy(configBottalker->SERVER, p);
		}
		else if( substring(temp, "CLIENT") >= 0)
		{
			strcpy(configBottalker->CLIENT, p);
		}
	}
}

/*Read the IPs that users don't want to replace*/
void ReadIPExclusionRecords(char * fileRead)
{
	FILE * fpRead = NULL;
	char * p = NULL;
	char ip[16];
	char buffer[MAX_SIZE];
	struct ip_list * lastIPExclusion = NULL;
	if((fpRead = fopen(fileRead, "r")) == NULL)  //open the file to read
	{
		fprintf(stderr, "Line %d: Open file: %s failed\n", __LINE__, fileRead);
		exit(1);
	}
	while(!feof(fpRead))
	{
		fgets(buffer, sizeof(buffer), fpRead);
		if(feof(fpRead))
		{
			break;
		}
		p = strtok(buffer, "\n");
		if(p)
		{
			strcpy(ip, p);
		}
		struct ip_list * newIPExclusion = (struct ip_list*)malloc(sizeof(struct ip_list));
		strcpy(newIPExclusion->ip, ip);
		if(ipExclusion == NULL)
		{
			ipExclusion = newIPExclusion;
			lastIPExclusion = newIPExclusion;
		}
		else
		{
			lastIPExclusion->next = newIPExclusion;
			lastIPExclusion = newIPExclusion;
		}
	}
	struct ip_list * iteIPExclusion = ipExclusion;
	while(iteIPExclusion != NULL)
	{
		printf("exclusion ip: %s\n", iteIPExclusion->ip);
		iteIPExclusion = iteIPExclusion->next;
	}
}

int CheckExclusionIP(char * ip)
{
	struct ip_list * iteIPExclusion = ipExclusion;
	while(iteIPExclusion != NULL)
	{
		if(strcmp(iteIPExclusion->ip, ip) == 0)
		{
			return 1;
		}
		iteIPExclusion = iteIPExclusion->next;
	}
	return 0;
}

/*Read the IPs that users don't want to replace*/
void ReadPortExclusionRecords(char * fileRead)
{
	FILE * fpRead = NULL;
	char * p = NULL;
	int port = 0;
	char buffer[MAX_SIZE];
	struct port_list * lastPortExclusion = NULL;
	if((fpRead = fopen(fileRead, "r")) == NULL)  //open the file to read
	{
		fprintf(stderr, "Line %d: Open file: %s failed\n", __LINE__, fileRead);
		exit(1);
	}
	while(!feof(fpRead))
	{
		fgets(buffer, sizeof(buffer), fpRead);
		if(feof(fpRead))
		{
			break;
		}
		p = strtok(buffer, "\n");
		if(p)
		{
			port = atoi(p);
		}
		struct port_list * newPortExclusion = (struct port_list*)malloc(sizeof(struct port_list));
		newPortExclusion->port = port;
		newPortExclusion->next = NULL;
		if(portExclusion == NULL)
		{
			portExclusion = newPortExclusion;
			lastPortExclusion = newPortExclusion;
		}
		else
		{
			lastPortExclusion->next = newPortExclusion;
			lastPortExclusion = newPortExclusion;
		}
	}
	struct port_list * itePortExclusion = portExclusion;
	while(itePortExclusion != NULL)
	{
		printf("exclusion port: %d\n", itePortExclusion->port);
		itePortExclusion = itePortExclusion->next;
	}
}

int CheckExclusionPort(int port)
{
	struct port_list * itePortExclusion = portExclusion;
	while(itePortExclusion != NULL)
	{
		if(itePortExclusion->port == port)
		{
			return 1;
		}
		itePortExclusion = itePortExclusion->next;
	}
	return 0;
}

void ReadFlowRecords(char * fileRead)
{
	FILE * fpRead = NULL;
	char * p = NULL;
	char srcIP[16];
	char destIP[16];
	int srcPort = 0;
	int destPort = 0;
	int proto = 0;
	char buffer[MAX_SIZE];
	struct flow_record * iteFlowRecord;
	if((fpRead = fopen(fileRead, "r")) == NULL)  //open the file     to read
	{
		fprintf(stderr, "Line %d: Open file: %s failed\n", __LINE__, fileRead);
		exit(1);
	}
	while(!feof(fpRead))
	{
		fgets(buffer, sizeof(buffer), fpRead);
		if(feof(fpRead))
		{
			break;
		}
		p = strtok(buffer, " ");
		if(p)
		{
			strcpy(srcIP, p);
		}
		p = strtok(NULL, " ");
		if(p)
		{
			srcPort = atoi(p);
		}
		p = strtok(NULL, " ");
		if(p)
		{
			strcpy(destIP, p);
		}
		p = strtok(NULL, " ");
		if(p)
		{
			destPort = atoi(p);
		}
		p = strtok(NULL, " ");
		if(p)
		{
			proto = atoi(p);
		}
		struct flow_record * newFlowRecord = (struct flow_record *)malloc(sizeof(struct flow_record));
		strcpy(newFlowRecord->src_ip, srcIP);
		newFlowRecord->src_port = srcPort;
		strcpy(newFlowRecord->dest_ip, destIP);
		newFlowRecord->dest_port = destPort;
		newFlowRecord->proto = proto;
		newFlowRecord->next = NULL;
		if(flowExtractHead == NULL)
		{
			flowExtractHead = newFlowRecord;
			flowExtractLast = newFlowRecord;
		}
		else
		{
			flowExtractLast->next = newFlowRecord;
			flowExtractLast = newFlowRecord;
		}
	}
	iteFlowRecord = flowExtractHead;
	while(iteFlowRecord)
	{
		//printf("src_ip: %s, src_port: %d, dest_ip: %s, dest_port: %d\n", iteFlowRecord->src_ip, iteFlowRecord->src_port, iteFlowRecord->dest_ip, iteFlowRecord->dest_port);
		iteFlowRecord = iteFlowRecord->next;
	}
}

void select_random_key(char *key, int b)
{
	RAND_bytes(key, b);
	/*int i;
	printf("key: \n");
	for(i=0; i<b-1; i++)
	{
		printf("%02X:", key[i]);
	}
	printf("%02X\n", key[b - 1]);*/
}
void select_random_iv(char *iv, int b)
{
	RAND_pseudo_bytes(iv, b);
	/*int i = 0;
	for(i=0; i<b-1; i++)
	{
		printf("%02X:", iv[i]);
	}*/
}

char * encrypt_OpenSSL(EVP_CIPHER_CTX *ctx, char *data, int inl, int *rb)
{
	char *ret;
	int  i, tmp, ol;
	ol = 0;
	ret = (char *)malloc(inl + EVP_CIPHER_CTX_block_size(ctx));
	EVP_EncryptUpdate(ctx, &ret[ol], &tmp, &data[ol], inl);
	ol += tmp;
	EVP_EncryptFinal(ctx, &ret[ol], &tmp);
	*rb = ol + tmp;
	return ret;
}

char * decrypt_OpenSSL(EVP_CIPHER_CTX *ctx, char *ct, int inl)
{
	/* We're going to null-terminate the plaintext under the assumption it's
	 * non-null terminated ASCII text. The null can be ignored otherwise.
	 */
	char *pt = (char *)malloc(inl + EVP_CIPHER_CTX_block_size(ctx) + 1);
	int ol;
	EVP_DecryptUpdate(ctx, pt, &ol, ct, inl);
	if (!ol) /* there's no block to decrypt */
	{
		free(pt);
		return NULL;
	}
	pt[ol] = 0;
	return pt;
}

int get_element_number(char * buffer)
{
	char temp[2048];
	char * p = NULL;
	int keyBytesCount = 0;
	//read and parse the key
	p = strtok(buffer, " ");
	if(p)
	{
		keyBytesCount++;
	}
	while(1)
	{
		p = strtok(NULL, " ");
		if(p)
		{
			keyBytesCount++;
		}
		else
		{
			break;
		}
	}
	//printf("key has %d bytes\n", key_bytes_count);
	return keyBytesCount;
}

int extract_key_iv(char * buffer, char * array)
{
	char * p = NULL;
	p = NULL;
	int count = 0;
	p = strtok(buffer, " ");
	if(p)
	{
		array[count] = atoi(p);
		count++;
	}
	while(1)
	{
		p = strtok(NULL, " ");
		if(p)
		{
			array[count] = atoi(p);
			count++;
		}
		else
		{
			break;
		}
	}
}

int set_encryption_algorithm(char * encryptionAlgorithm, EVP_CIPHER_CTX * ctx, char * key, char * iv)
{
	//des: EVP_des_cbc(void), EVP_des_ecb(void), EVP_des_cfb(void), EVP_des_ofb(void)
	//cipherBlockSize: 8, cipherKeyLength: 8, cipherIvLength: 8
	if(strcmp(encryptionAlgorithm, "EVP_des_cbc") == 0)
	{
		EVP_EncryptInit(ctx, EVP_des_cbc(), key, iv);
	}
	//cipherBlockSize: 8, cipherKeyLength: 8, cipherIvLength: 0
	else if(strcmp(encryptionAlgorithm, "EVP_des_ecb") == 0)
	{
		EVP_EncryptInit(ctx, EVP_des_ecb(), key, iv);
	}
	//cipherBlockSize: 1, cipherKeyLength: 8, cipherIvLength: 8
	else if(strcmp(encryptionAlgorithm, "EVP_des_cfb") == 0)
	{
		EVP_EncryptInit(ctx, EVP_des_cfb(), key, iv);	
	}
	//cipherBlockSize: 1, cipherKeyLength: 8, cipherIvLength: 8
	else if(strcmp(encryptionAlgorithm, "EVP_des_ofb") == 0)
	{
		EVP_EncryptInit(ctx, EVP_des_ofb(), key, iv);
	}
	//des 2 key: EVP_des_ede_cbc(void), EVP_des_ede(), EVP_des_ede_ofb(void), EVP_des_ede_cfb(void)
	//cipherBlockSize: 8, cipherKeyLength: 16, cipherIvLength: 8
	else if(strcmp(encryptionAlgorithm, "EVP_des_ede_cbc") == 0)
	{
		EVP_EncryptInit(ctx, EVP_des_ede_cbc(), key, iv);
	}
	//cipherBlockSize: 8, cipherKeyLength: 16, cipherIvLength: 0
	else if(strcmp(encryptionAlgorithm, "EVP_des_ede") == 0)
	{
		EVP_EncryptInit(ctx, EVP_des_ede(), key, iv);
	}
	//cipherBlockSize: 1, cipherKeyLength: 16, cipherIvLength: 8
	else if(strcmp(encryptionAlgorithm, "EVP_des_ede_ofb") == 0)
	{
		EVP_EncryptInit(ctx, EVP_des_ede_ofb(), key, iv);
	}
	//cipherBlockSize: 1, cipherKeyLength: 16, cipherIvLength: 8
	else if(strcmp(encryptionAlgorithm, "EVP_des_ede_cfb") == 0)
	{
		EVP_EncryptInit(ctx, EVP_des_ede_cfb(), key, iv);
	}
	//des 3 key: EVP_des_ede3_cbc(void), EVP_des_ede3(), EVP_des_ede3_ofb(void), EVP_des_ede3_cfb(void)
	//cipherBlockSize: 8, cipherKeyLength: 24, cipherIvLength: 8
	else if(strcmp(encryptionAlgorithm, "EVP_des_ede3_cbc") == 0)
	{
		EVP_EncryptInit(ctx, EVP_des_ede3_cbc(), key, iv);
	}
	//cipherBlockSize: 8, cipherKeyLength: 24, cipherIvLength: 0
	else if(strcmp(encryptionAlgorithm, "EVP_des_ede3") == 0)
	{
		EVP_EncryptInit(ctx, EVP_des_ede3(), key, iv);
	}
	//cipherBlockSize: 1, cipherKeyLength: 24, cipherIvLength: 8
	else if(strcmp(encryptionAlgorithm, "EVP_des_ede3_ofb") == 0)
	{
		EVP_EncryptInit(ctx, EVP_des_ede3_ofb(), key, iv);
	}
	//cipherBlockSize: 1, cipherKeyLength: 24, cipherIvLength: 8
	else if(strcmp(encryptionAlgorithm, "EVP_des_ede3_cfb") == 0)
	{
		EVP_EncryptInit(ctx, EVP_des_ede3_cfb(), key, iv);
	}
	//desx: EVP_desx_cbc(void)
	//cipherBlockSize: 8, cipherKeyLength: 24, cipherIvLength: 8
	else if(strcmp(encryptionAlgorithm, "EVP_desx_cbc") == 0)
	{
		EVP_EncryptInit(ctx, EVP_desx_cbc(), key, iv);
	}
	//rc4: EVP_rc4(void), This is a variable key length cipher with default key length 128 bits
	//cipherBlockSize: 1, cipherKeyLength: 16, cipherIvLength: 0
	else if(strcmp(encryptionAlgorithm, "EVP_rc4") == 0)
	{
		EVP_EncryptInit(ctx, EVP_rc4(), key, iv);
	}
	//rc4 40 bit key: EVP_rc4_40(void) RC4 stream cipher with 40 bit key length
	//cipherBlockSize: 1, cipherKeyLength: 5, cipherIvLength: 0
	else if(strcmp(encryptionAlgorithm, "EVP_rc4_40") == 0)
	{
		EVP_EncryptInit(ctx, EVP_rc4_40(), key, iv);
	}
	//rc2: EVP_rc2_cbc(void), EVP_rc2_ecb(void), EVP_rc2_cfb(void), EVP_rc2_ofb(void), EVP_rc2_40_cbc(void), EVP_rc2_64_cbc(void)
	//cipherBlockSize: 8, cipherKeyLength: 16, cipherIvLength: 8
	else if(strcmp(encryptionAlgorithm, "EVP_rc2_cbc") == 0)
	{
		EVP_EncryptInit(ctx, EVP_rc2_cbc(), key, iv);
	}
	//cipherBlockSize: 8, cipherKeyLength: 16, cipherIvLength: 0
	else if(strcmp(encryptionAlgorithm, "EVP_rc2_ecb") == 0)
	{
		EVP_EncryptInit(ctx, EVP_rc2_ecb(), key, iv);
	}
	//cipherBlockSize: 1, cipherKeyLength: 16, cipherIvLength: 8
	else if(strcmp(encryptionAlgorithm, "EVP_rc2_cfb") == 0)
	{
		EVP_EncryptInit(ctx, EVP_rc2_cfb(), key, iv);
	}
	//cipherBlockSize: 1, cipherKeyLength: 16, cipherIvLength: 8
	else if(strcmp(encryptionAlgorithm, "EVP_rc2_ofb") == 0)
	{
		EVP_EncryptInit(ctx, EVP_rc2_ofb(), key, iv);
	}
	//cipherBlockSize: 8, cipherKeyLength: 5, cipherIvLength: 8
	else if(strcmp(encryptionAlgorithm, "EVP_rc2_40_cbc") ==0 )
	{
		EVP_EncryptInit(ctx, EVP_rc2_40_cbc(), key, iv);
	}
	//cipherBlockSize: 8, cipherKeyLength: 8, cipherIvLength: 8
	else if(strcmp(encryptionAlgorithm, "EVP_rc2_64_cbc") == 0)
	{
		EVP_EncryptInit(ctx, EVP_rc2_64_cbc(), key, iv);
	}
	//Blowfish: EVP_bf_cbc(void), EVP_bf_ecb(void), EVP_bf_cfb(void), EVP_bf_ofb(void)
	//cipherBlockSize: 8, cipherKeyLength: 16, cipherIvLength: 8
	else if(strcmp(encryptionAlgorithm, "EVP_bf_cbc") == 0)
	{
		EVP_EncryptInit(ctx, EVP_bf_cbc(), key, iv);
	}
	//cipherBlockSize: 8, cipherKeyLength: 16, cipherIvLength: 0
	else if(strcmp(encryptionAlgorithm, "EVP_bf_ecb") == 0)
	{
		EVP_EncryptInit(ctx, EVP_bf_ecb(), key, iv);
	}
	//cipherBlockSize: 1, cipherKeyLength: 16, cipherIvLength: 8
	else if(strcmp(encryptionAlgorithm, "EVP_bf_cfb") == 0)
	{
		EVP_EncryptInit(ctx, EVP_bf_cfb(), key, iv);
	}
	//cipherBlockSize: 1, cipherKeyLength: 16, cipherIvLength: 8
	else if(strcmp(encryptionAlgorithm, "EVP_bf_ofb") == 0)
	{
		EVP_EncryptInit(ctx, EVP_bf_ofb(), key, iv);
	}
	//CAST: EVP_cast5_cbc(void), EVP_cast5_ecb(void), EVP_cast5_cfb(void), EVP_cast5_ofb(void)
	//cipherBlockSize: 8, cipherKeyLength: 16, cipherIvLength: 8
	else if(strcmp(encryptionAlgorithm, "EVP_cast5_cbc") == 0)
	{
		EVP_EncryptInit(ctx, EVP_cast5_cbc(), key, iv);
	}
	//cipherBlockSize: 8, cipherKeyLength: 16, cipherIvLength: 0
	else if(strcmp(encryptionAlgorithm, "EVP_cast5_ecb") == 0)
	{
		EVP_EncryptInit(ctx, EVP_cast5_ecb(), key, iv);
	}
	//cipherBlockSize: 1, cipherKeyLength: 16, cipherIvLength: 8
	else if(strcmp(encryptionAlgorithm, "EVP_cast5_cfb") == 0)
	{
		EVP_EncryptInit(ctx, EVP_cast5_cfb(), key, iv);
	}
	//cipherBlockSize: 1, cipherKeyLength: 16, cipherIvLength: 8
	else if(strcmp(encryptionAlgorithm, "EVP_cast5_ofb") == 0)
	{
		EVP_EncryptInit(ctx, EVP_cast5_ofb(), key, iv);
	}
	//AES: EVP_aes_128_ecb(), EVP_aes_128_cbc(), EVP_aes_192_ecb(), EVP_aes_192_cbc(), EVP_aes_256_ecb(), EVP_aes_256_cbc()
	//cipherBlockSize: 16, cipherKeyLength: 16, cipherIvLength: 0
	else if(strcmp(encryptionAlgorithm, "EVP_aes_128_ecb") == 0)
	{
		EVP_EncryptInit(ctx, EVP_aes_128_ecb(), key, iv);
	}
	//cipherBlockSize: 16, cipherKeyLength: 16, cipherIvLength: 16
	else if(strcmp(encryptionAlgorithm, "EVP_aes_128_cbc") == 0)
	{
		EVP_EncryptInit(ctx, EVP_aes_128_cbc(), key, iv);
	}
	//cipherBlockSize: 16, cipherKeyLength: 16, cipherIvLength: 16
	else if(strcmp(encryptionAlgorithm, "EVP_aes_128_cfb") == 0)
	{
		EVP_EncryptInit(ctx, EVP_aes_128_cfb(), key, iv);
	}
	//cipherBlockSize: 16, cipherKeyLength: 16, cipherIvLength: 16
	else if(strcmp(encryptionAlgorithm, "EVP_aes_128_ofb") == 0)
	{
		EVP_EncryptInit(ctx, EVP_aes_128_ofb(), key, iv);
	}
	//cipherBlockSize: 16, cipherKeyLength: 24, cipherIvLength: 0
	else if(strcmp(encryptionAlgorithm, "EVP_aes_192_ecb") == 0)
	{
		EVP_EncryptInit(ctx, EVP_aes_192_ecb(), key, iv);
	}
	//cipherBlockSize: 16, cipherKeyLength: 24, cipherIvLength: 16
	else if(strcmp(encryptionAlgorithm, "EVP_aes_192_cbc") == 0)
	{
		EVP_EncryptInit(ctx, EVP_aes_192_cbc(), key, iv);
	}
	//cipherBlockSize: 16, cipherKeyLength: 24, cipherIvLength: 16
	else if(strcmp(encryptionAlgorithm, "EVP_aes_192_cfb") == 0)
	{
		EVP_EncryptInit(ctx, EVP_aes_192_cfb(), key, iv);
	}
	//cipherBlockSize: 16, cipherKeyLength: 24, cipherIvLength: 16
	else if(strcmp(encryptionAlgorithm, "EVP_aes_192_ofb") == 0)
	{
		EVP_EncryptInit(ctx, EVP_aes_192_ofb(), key, iv);
	}
	//cipherBlockSize: 16, cipherKeyLength: 32, cipherIvLength: 0
	else if(strcmp(encryptionAlgorithm, "EVP_aes_256_ecb") == 0)
	{
		EVP_EncryptInit(ctx, EVP_aes_256_ecb(), key, iv);
	}
	//cipherBlockSize: 16, cipherKeyLength: 32, cipherIvLength: 16
	else if(strcmp(encryptionAlgorithm, "EVP_aes_256_cbc") == 0)
	{
		EVP_EncryptInit(ctx, EVP_aes_256_cbc(), key, iv);
	}
	//cipherBlockSize: 16, cipherKeyLength: 32, cipherIvLength: 16
	else if(strcmp(encryptionAlgorithm, "EVP_aes_256_cfb") == 0)
	{
		EVP_EncryptInit(ctx, EVP_aes_256_cfb(), key, iv);
	}
	//cipherBlockSize: 16, cipherKeyLength: 32, cipherIvLength: 16
	else if(strcmp(encryptionAlgorithm, "EVP_aes_256_ofb") == 0)
	{
		EVP_EncryptInit(ctx, EVP_aes_256_ofb(), key, iv);
	}
	else
	{
		printf("The entered encryption algorithm is not correct\n");
		exit(1);
	}

	return 0;
}

int payload_checksum(uint16_t * checksum, char * payload, char * newPayload, int length)
{
	uint32_t sum = 0;
	uint32_t sum_ = 0;
	while(length>0)
	{
		if(length%2==1)
		{
			uint16_t new_data = ((uint16_t)newPayload[length-1] << 8)&0xFFFF;
			uint16_t old_data = ((uint16_t)payload[length-1] << 8)&0xFFFF;
			sum_ = sum_ + new_data;
			sum = (~htons(*checksum) & 0xFFFF) 
				+ (~(old_data) & 0xFFFF) 
				+ (new_data);
			sum = (sum & 0xFFFF) + (sum >> 16);
			*checksum = htons(~(sum + (sum >> 16)));
			length--;
		}
		else
		{
			uint16_t new_data = (((uint16_t)newPayload[length-1])&0x00FF) + ((((uint16_t)newPayload[length-2])<<8)&0xFFFF);
			uint16_t old_data = (((uint16_t)payload[length-1])&0x00FF) + ((((uint16_t)payload[length-2])<<8)&0xFFFF);
			sum_ = sum_ + new_data; 
			sum = (~htons(*checksum) & 0xFFFF) 
				+ (~(old_data) & 0xFFFF) 
				+ (new_data);
			sum = (sum & 0xFFFF) + (sum >> 16);
			*checksum = htons(~(sum + (sum >> 16)));
			length=length-2;
		}
	}
}

/* Incrementally update a checksum */
void update_in_cksum(uint16_t *csum, uint16_t old, uint16_t new)
{
	uint32_t sum = (~htons(*csum) & 0xFFFF) 
		+ (~htons(old) & 0xFFFF) 
		+ htons(new);
	sum = (sum & 0xFFFF) + (sum >> 16);
	*csum = htons(~(sum + (sum >> 16)));
}

void update_in_cksum32(uint16_t *csum, uint32_t old, uint32_t new)
{
	update_in_cksum(csum,(uint16_t)(old&0xFFFF),(uint16_t)(new&0xFFFF));
	update_in_cksum(csum,(uint16_t)(old>>16),(uint16_t)(new>>16));
}

//XOR encryption
void encrypt_xor(char * StrToEncrypt, char * StrEncrtypted, char* key, int length)
{
	int keyCount = 0; //Used to restart key if strlen(key) < strlen(encrypt)
	int encryptByte;
	int loop = 0;
	//Loop through each byte of file until EOF
	for(loop = 0; loop < length; loop++)
	{
		//XOR the data and write it to a file
		StrEncrtypted[loop] = StrToEncrypt[loop] ^ key[keyCount];
		keyCount++;
		if(keyCount == strlen(key))
		{
			keyCount = 0;
		}
	}
}


int ReplaceIP_SSL(libtrace_ip_t * copyIP, char * IPOriginal, char * IPReplace, int sys)
{
	int loop = 0;
	char * p = NULL;
	int OctOriginalIP[4];
	int OctReplaceIP[4];
	char tempOri[16];
	char tempRep[16];
	//char replace_IP[16];
	memset(tempOri, '\0', sizeof(tempOri));
	strcpy(tempOri, IPOriginal);
	p = NULL;
	p = strtok(tempOri, ".");
	if(p)
	{
		OctOriginalIP[0] = atoi(p);
	}
	for(loop = 1; loop < 4; loop++)
	{
		p = strtok(NULL, ".");
		if(p)
		{
			OctOriginalIP[loop] = atoi(p);
		}
	}
	uint32_t IPToReplace = OctOriginalIP[3]*256*256*256 + OctOriginalIP[2]*256*256 + OctOriginalIP[1]*256 + OctOriginalIP[0];

	memset(tempRep, '\0', sizeof(tempRep));
	strcpy(tempRep, IPReplace);
	p = NULL;
	p = strtok(tempRep, ".");
	if(p)
	{
		OctReplaceIP[0] = atoi(p);
	}
	for(loop = 1; loop < 4; loop++)
	{
		p = strtok(NULL, ".");
		if(p)
		{
			OctReplaceIP[loop] = atoi(p);
		}
	}

	uint32_t oldIP = 0;
	//printf("IP_to_replace: %u, src_ip: %u, dest_ip: %u\n", IP_to_replace, copy_ip->ip_src.s_addr, copy_ip->ip_dst.s_addr);
	if(sys == 0)
	{
		oldIP = copyIP->ip_src.s_addr;
	}
	else if(sys == 1)
	{
		oldIP = copyIP->ip_dst.s_addr;
	}
	else
	{
		//printf("No IP replacement Match\n");
		return;
	}
	uint32_t newIP = 0;
	struct libtrace_tcp *tcp;
	struct libtrace_udp *udp;
	tcp=trace_get_tcp_from_ip(copyIP,NULL);
	udp=trace_get_udp_from_ip(copyIP,NULL);
	for(loop=0; loop < 4; loop++)
	{
		newIP = newIP*256 + OctReplaceIP[loop];
	}
	update_in_cksum32(&copyIP->ip_sum, oldIP, htonl(newIP));
	if(tcp)
	{
		update_in_cksum32(&tcp->check, oldIP, htonl(newIP));
	}
	if(udp)
	{
		update_in_cksum32(&udp->check, oldIP, htonl(newIP));
	}
	if(sys == 0)
	{
		copyIP->ip_src.s_addr = htonl(newIP);
	}
	else if(sys == 1)
	{
		copyIP->ip_dst.s_addr = htonl(newIP);
	}
}


int IPBelongTo(char * ip1, char * ip2, int subnet)
{
	int sysReplaceSrc = 0;
	int sysReplaceDest = 0;
	int loop = 0;
	char * p = NULL;
	int octetIP1[4];
	int octetIP2[4];
	char temp[16];
	memset(temp, '\0', sizeof(temp));
	strcpy(temp, ip1);
	p = NULL;
	p = strtok(temp, ".");
	if(p)
	{
		octetIP1[0] = atoi(p);
	}
	for(loop = 1; loop < 4; loop++)
	{
		p = strtok(NULL, ".");
		if(p)
		{
			octetIP1[loop] = atoi(p);
		}
	}

	memset(temp, '\0', sizeof(temp));
	strcpy(temp, ip2);
	p = NULL;
	p = strtok(temp, ".");
	if(p)
	{
		octetIP2[0] = atoi(p);
	}
	for(loop = 1; loop < 4; loop++)
	{
		p = strtok(NULL, ".");
		if(p)
		{
			octetIP2[loop] = atoi(p);
		}
	}

	for(loop = 0; loop < subnet/8; loop++)
	{
		if(octetIP1[loop] != octetIP2[loop])
		{
			break;
		}
	}
	if(loop == subnet/8)
	{
		//ip2 belongs to ip1
		return 0;
	}
	else
	{
		//ip2 doesn't belong to ip1
		return 1;
	}
}

int ReplaceIP_All(libtrace_ip_t * copyIP, char * IPOriginal, char * IPReplace, int oriSubnet, int replaceSubnet, int srcDest)
{
	int sysReplaceSrc = 0;
	int sysReplaceDest = 0;
	int loop = 0;
	char * p = NULL;
	int OctOriginalIP[4];
	int OctReplaceIP[4];
	char tempOri[16];
	char tempRep[16];
	memset(tempOri, '\0', sizeof(tempOri));
	strcpy(tempOri, IPOriginal);
	p = NULL;
	p = strtok(tempOri, ".");
	if(p)
	{
		OctOriginalIP[0] = atoi(p);
	}
	for(loop = 1; loop < 4; loop++)
	{
		p = strtok(NULL, ".");
		if(p)
		{
			OctOriginalIP[loop] = atoi(p);
		}
	}
	uint8_t srcDestIPOctet[4];
	for (loop=0; loop<4; loop++)
	{
		if(srcDest == 0)
		{
			srcDestIPOctet[loop] = ( copyIP->ip_src.s_addr >> (loop*8) ) & 0xFF;
		}
		if(srcDest == 1)
		{
			srcDestIPOctet[loop] = ( copyIP->ip_dst.s_addr >> (loop*8) ) & 0xFF;
		}
	}

	memset(tempRep, '\0', sizeof(tempRep));
	strcpy(tempRep, IPReplace);
	p = NULL;
	p = strtok(tempRep, ".");
	if(p)
	{
		OctReplaceIP[0] = atoi(p);
	}
	for(loop = 1; loop < 4; loop++)
	{
		p = strtok(NULL, ".");
		if(p)
		{
			OctReplaceIP[loop] = atoi(p);
		}
	}

	uint32_t oldIP = 0;
	for(loop=0; loop < oriSubnet/8; loop++)
	{
		if(srcDestIPOctet[loop] != OctOriginalIP[loop]) 
		{
			if(srcDest == 0)
			{
				oldIP = copyIP->ip_src.s_addr;
			}
			if(srcDest == 1)
			{
				oldIP = copyIP->ip_dst.s_addr;
			}
			break;
		}
	}
	if(loop == oriSubnet/8)	//the ip belongs to the local network
	{
		return;
	}
	uint32_t newIP = 0;
	struct libtrace_tcp *tcp;
	struct libtrace_udp *udp;
	tcp=trace_get_tcp_from_ip(copyIP,NULL);
	udp=trace_get_udp_from_ip(copyIP,NULL);
	for(loop=0; loop < replaceSubnet/8; loop++)
	{
		newIP = newIP*256 + OctReplaceIP[loop];
	}
	for(loop=replaceSubnet/8; loop<4; loop++)
	{
		newIP = newIP*256 + srcDestIPOctet[loop];
	}
	update_in_cksum32(&copyIP->ip_sum, oldIP, htonl(newIP));
	if(tcp)
	{
		update_in_cksum32(&tcp->check, oldIP, htonl(newIP));
	}
	if(udp)
	{
		update_in_cksum32(&udp->check, oldIP, htonl(newIP));
	}
	if( srcDest == 0)
	{
		copyIP->ip_src.s_addr = htonl(newIP);
	}
	else if( srcDest == 1)
	{
		copyIP->ip_dst.s_addr = htonl(newIP);
	}
}

int ReplaceIP_ALL(libtrace_ip_t * copyIP, char * IPOriginal, char * IPReplace, int subnet)
{
	int sysReplaceSrc = 0;
	int sysReplaceDest = 0;
	int loop = 0;
	char * p = NULL;
	int OctOriginalIP[4];
	int OctReplaceIP[4];
	char tempOri[16];
	char tempRep[16];
	memset(tempOri, '\0', sizeof(tempOri));
	strcpy(tempOri, IPOriginal);
	p = NULL;
	p = strtok(tempOri, ".");
	if(p)
	{
		OctOriginalIP[0] = atoi(p);
	}
	for(loop = 1; loop < 4; loop++)
	{
		p = strtok(NULL, ".");
		if(p)
		{
			OctOriginalIP[loop] = atoi(p);
		}
	}
	uint32_t IPToReplace = OctOriginalIP[3]*256*256*256 + OctOriginalIP[2]*256*256 + OctOriginalIP[1]*256 + OctOriginalIP[0];
	uint8_t srcIPOctet[4];
	uint8_t destIPOctet[4];
	for (loop=0; loop<4; loop++)
	{
		srcIPOctet[loop] = ( copyIP->ip_src.s_addr >> (loop*8) ) & 0xFF;
	}
	for (loop=0; loop<4; loop++)
	{
		destIPOctet[loop] = ( copyIP->ip_dst.s_addr >> (loop*8) ) & 0xFF;
	}

	memset(tempRep, '\0', sizeof(tempRep));
	strcpy(tempRep, IPReplace);
	p = NULL;
	p = strtok(tempRep, ".");
	if(p)
	{
		OctReplaceIP[0] = atoi(p);
	}
	for(loop = 1; loop < 4; loop++)
	{
		p = strtok(NULL, ".");
		if(p)
		{
			OctReplaceIP[loop] = atoi(p);
		}
	}

	uint32_t oldIP = 0;
	if( (srcIPOctet[0] != OctOriginalIP[0]) || (srcIPOctet[1] != OctOriginalIP[1]) )
	{
		sysReplaceSrc = 1;
		oldIP = copyIP->ip_src.s_addr;
	}
	else
	{
		if( (destIPOctet[0] != OctOriginalIP[0]) || (destIPOctet[1] != OctOriginalIP[1]) )
		{
			sysReplaceDest = 1;
			oldIP = copyIP->ip_dst.s_addr;
		}
		else
		{
			return;
		}
	}

	uint32_t newIP = 0;
	struct libtrace_tcp *tcp;
	struct libtrace_udp *udp;
	tcp=trace_get_tcp_from_ip(copyIP,NULL);
	udp=trace_get_udp_from_ip(copyIP,NULL);
	for(loop=0; loop < subnet/8; loop++)
	{
		newIP = newIP*256 + OctReplaceIP[loop];
	}
	for(loop=subnet/8; loop<4; loop++)
	{
		if(sysReplaceSrc == 1)
		{
			newIP = newIP*256 + srcIPOctet[loop];
		}
		if(sysReplaceDest == 1)
		{
			newIP = newIP*256 + destIPOctet[loop];
		}
	}
	update_in_cksum32(&copyIP->ip_sum, oldIP, htonl(newIP));
	if(tcp)
	{
		update_in_cksum32(&tcp->check, oldIP, htonl(newIP));
	}
	if(udp)
	{
		update_in_cksum32(&udp->check, oldIP, htonl(newIP));
	}
	if(sysReplaceSrc == 1)
	{
		copyIP->ip_src.s_addr = htonl(newIP);
	}
	else if(sysReplaceDest == 1)
	{
		copyIP->ip_dst.s_addr = htonl(newIP);
	}
}


int ReplaceIP(libtrace_ip_t * copyIP, char * IPOriginal, char * IPReplace, int subnet, int srcDest)
{
	int sysReplaceSrc = 0;
	int sysReplaceDest = 0;
	int loop = 0;
	char * p = NULL;
	int OctOriginalIP[4];
	int OctReplaceIP[4];
	char tempOri[16];
	char tempRep[16];
	memset(tempOri, '\0', sizeof(tempOri));
	strcpy(tempOri, IPOriginal);
	p = NULL;
	p = strtok(tempOri, ".");
	if(p)
	{
		OctOriginalIP[0] = atoi(p);
	}
	for(loop = 1; loop < 4; loop++)
	{
		p = strtok(NULL, ".");
		if(p)
		{
			OctOriginalIP[loop] = atoi(p);
		}
	}
	uint32_t IPToReplace = OctOriginalIP[3]*256*256*256 + OctOriginalIP[2]*256*256 + OctOriginalIP[1]*256 + OctOriginalIP[0];
	uint8_t srcDestIPOctet[4];
	for (loop=0; loop<4; loop++)
	{
		if(srcDest == 0)
		{
			srcDestIPOctet[loop] = ( copyIP->ip_src.s_addr >> (loop*8) ) & 0xFF;
		}
		if(srcDest == 1)
		{
			srcDestIPOctet[loop] = ( copyIP->ip_dst.s_addr >> (loop*8) ) & 0xFF;
		}
	}

	memset(tempRep, '\0', sizeof(tempRep));
	strcpy(tempRep, IPReplace);
	p = NULL;
	p = strtok(tempRep, ".");
	if(p)
	{
		OctReplaceIP[0] = atoi(p);
	}
	for(loop = 1; loop < 4; loop++)
	{
		p = strtok(NULL, ".");
		if(p)
		{
			OctReplaceIP[loop] = atoi(p);
		}
	}

	uint32_t oldIP = 0;
	for(loop = 0; loop < subnet/8; loop++)
	{
		if(srcDestIPOctet[loop] != OctOriginalIP[loop])
		{
			break;
		}
	}
	if(loop == subnet/8)
	{
		if(srcDest == 0)
		{
			oldIP = copyIP->ip_src.s_addr;
		}
		if(srcDest == 1)
		{
			oldIP = copyIP->ip_dst.s_addr;
		}
	}
	else
	{
		return;
	}

	uint32_t newIP = 0;
	struct libtrace_tcp *tcp;
	struct libtrace_udp *udp;
	tcp=trace_get_tcp_from_ip(copyIP,NULL);
	udp=trace_get_udp_from_ip(copyIP,NULL);
	for(loop=0; loop < subnet/8; loop++)
	{
		newIP = newIP*256 + OctReplaceIP[loop];
	}
	for(loop=subnet/8; loop<4; loop++)
	{
		newIP = newIP*256 + srcDestIPOctet[loop];
	}
	update_in_cksum32(&copyIP->ip_sum, oldIP, htonl(newIP));
	if(tcp)
	{
		update_in_cksum32(&tcp->check, oldIP, htonl(newIP));
	}
	if(udp)
	{
		update_in_cksum32(&udp->check, oldIP, htonl(newIP));
	}
	if(srcDest == 0)
	{
		copyIP->ip_src.s_addr = htonl(newIP);
	}
	else
	{
		copyIP->ip_dst.s_addr = htonl(newIP);
	}
}

//read the port need to filter
int ReadPortFilters(char * portFilterFile, int * portFilterArray, int IPPortFileLines)
{
	FILE * fpRead = NULL;
	char buffer[256];
	int count = 0;
	char * p = NULL;

	if((fpRead=fopen(portFilterFile, "r")) == NULL)  //open the file to read
	{
		fprintf(stderr, "Read IP replacement file: %s failed\n", portFilterFile);
		exit(1);
	}
	while(!feof(fpRead))        //read the data file and analysis
	{
		memset(buffer, '\0', sizeof(buffer));
		fgets(buffer, sizeof(buffer), fpRead);
		if(feof(fpRead))
		{
			break;
		}
		p = strtok(buffer, " ");
		if(p)
		{
			portFilterArray[count] = atoi(p);
			count++;
		}
	}
	fclose(fpRead);
	return 0;
}

//calculate how many lines is in the file
int GetFileLineNumer(char * ipReplaceFile)
{
	FILE * fpRead = NULL;
	int count = 0;
	char buffer[1024];

	//printf("line: %d, file: %s\n", __LINE__, ipReplaceFile);

	if((fpRead=fopen(ipReplaceFile, "r")) == NULL)  //open the file to read
	{
		fprintf(stderr, "Read IP replacement file: %s failed\n", ipReplaceFile);
		exit(1);
	}
	while(!feof(fpRead))
	{
		memset(buffer, '\0', sizeof(buffer));
		fgets(buffer, sizeof(buffer), fpRead);
		if(feof(fpRead))
		{
			break;
		}
		count++;
	}
	fclose(fpRead);
	return count;
}

//check whether the port is in the filter array, return 1 if it is in, else return 0
int CheckPortFilters(int portToCheck, int * portFilterArray, int IPPortFileLines)
{
	int loop = 0;
	for(loop = 0; loop < IPPortFileLines; loop++)
	{
		if(portToCheck == portFilterArray[loop])
		{
			return 1;
		}
	}
	return 0;
}

int ReadExeMagicNumberFile(char * exeMagicNumberFile, char ** exeMagicNumberArray)
{
	FILE * fpRead = NULL;
	char buffer[1024];
	int count = 0;
	char * p = NULL;
	if((fpRead=fopen( exeMagicNumberFile, "r" )) == NULL)  //open the file to read
	{
		fprintf(stderr, "Read IP replacement file: %s failed\n", exeMagicNumberFile);
		exit(1);
	}
	while(!feof(fpRead))
	{
		memset(buffer, '\0', sizeof(buffer));
		fgets(buffer, sizeof(buffer), fpRead);

		if(feof(fpRead))
		{
			break;
		}
		p = strtok(buffer, "\n");
		if(p)
		{
			strcpy(exeMagicNumberArray[count], buffer);
			//printf("MG %d: %s\n", count, buffer);
			count++;
		}
	}
}

//read the ip anonymization records from file
int ReadIPReplaceFile(char * IPConfigFile, struct struct_IPReplace * IPReplaceArray)
{
	FILE * fpRead = NULL;
	char * p = NULL;
	char buffer[128];
	char originalIP[16];
	char replaceIP[16];
	int subnet = 0;
	int count = 0;

	if((fpRead=fopen(IPConfigFile, "r")) == NULL)  //open the file to read
	{
		fprintf(stderr, "Read IP replacement file: %s failed\n", IPConfigFile);
		exit(1);
	}
	while(!feof(fpRead))
	{
		memset(buffer, '\0', sizeof(buffer));
		memset(originalIP, '\0', sizeof(originalIP));
		memset(replaceIP, '\0', sizeof(replaceIP));
		fgets(buffer, sizeof(buffer), fpRead);

		if(feof(fpRead))
		{
			break;
		}
		p = strtok(buffer, " ");
		if(p)
		{
			strcpy(originalIP, p);
		}
		p = strtok(NULL, " ");
		if(p)
		{
			subnet = atoi(p);
		}
		p = strtok(NULL, " ");
		if(p)
		{
			strcpy(replaceIP, p);
		}
		strcpy(IPReplaceArray[count].original_IP, originalIP);
		strcpy(IPReplaceArray[count].replace_IP, replaceIP);
		IPReplaceArray[count].subnet = subnet;
		count++;
	}
	fclose(fpRead);
	return 0;
}

//check whether a string contents a sub-string, return the offset of the beginning of the sub-string, else return -1
int ContentString( char * Original, int remaining, int exeMagicNumberLines, char ** exeMagicNumberArray)
{
	int loop = 0;
	int loopInner = 0;
	int loopOuter = 0;
	int lenOriginal = strlen(Original);
	int lenStrToSearch;
	int Found = 0;
	char buffer[1024];

	for(loopOuter = 0; loopOuter < exeMagicNumberLines; loopOuter++)
	{
		memset(buffer, '\0', sizeof(buffer));
		strcpy(buffer, exeMagicNumberArray[loopOuter]);
		lenStrToSearch = strlen(buffer);

		for(loop=0; loop < remaining-lenStrToSearch; loop++)
		{
			Found = 0;
			for(loopInner=0; loopInner<lenStrToSearch; loopInner++)
			{
				if(Original[loop + loopInner] != buffer[loopInner])
				{
					Found = 1;
					break;
				}
			}
			if(Found == 0)
			{
				//printf("Found String: %s\n", buffer);
				return loop;	//The string Original contains StrToSearch
			}
		}
	}
	return -1;	//Not found
}

int SearchforString(char * temp, char * StrToSearch, int remaining)
{
	int loop_in = 0;
	int loop_out = 0;
	int len = strlen(StrToSearch);
	char buffer[len+1];
	for(loop_out=0; loop_out < remaining-len; loop_out++)
	{	
		memset(buffer, '\0', sizeof(buffer));
		memcpy(buffer, temp, len);
		if(strcmp(buffer, StrToSearch) == 0)
		{
			return 0;
		}
	}
	return 1;
}

static void usage()
{
	printf("	-a: specify the file including IPs that do not need to replaced when option -r is used");
	printf("	-b	specify the background traffic\n");
	printf("	-c: specify configuration file (not used currently, reserved for SSL emulation)\n");
	printf("	-d: specify the file including ports whose traffic will not be encrypted when option -P or -F is used\n");
	printf("	-e	specify encryption algorithm\n");
	printf("	-f	specify the flow to encrypt\n");
	printf("	-k	specify the key and iv file \n");
	printf("	-i	specify the input trace\n");
	printf("	-o	specify the output trace\n");
	printf("	-r	apply ip replacement, followed by the ip pair\n");
	printf("	-n: replace a single IP address.\n \
			option '-r' and '/32' need to be given (e.g., -n -r '192.168.9.5/32 178.162.181.84/32')\n");
	printf("	-N: replace a subnet of IP addresses.\n \
			option '-r' needs to be given (e.g., -n -r '192.168.9.5/24 178.162.181.84/24')\n");
	printf("	-l 	specify background traffic local network. E.g. -l '129.82.138.0/24'\n");
	printf("	-t	specify time adjustment\n");
	printf("	-M	specify traffic merge scheme. Two schemes are support:\n \
		1. direct: -M 'direct' merge the background traffic with botnet traffic directly\n \
		2. random selection: random select hosts in background traffic and assign botnet traffic on them -M '192.168.9.0'\n");
	printf("	-P	enable packet level encryption\n");
	printf("	-F	enable flow level encryption\n");
	printf("	-h	display this help and exit\n");
}

int extract_ip_port(char * inputPcapFile, struct flow_record * flowEntry)
{
	FILE * fpIPPort = NULL;
	int psize = 0;
	libtrace_t *trace = 0;
	libtrace_packet_t *pkt = trace_create_packet();
	
	// Open traces for reading and writing.
	trace = trace_create(inputPcapFile);
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

	int traceOffset = 0;
	psize = trace_read_packet(trace, pkt);
	if (psize == 0) {
		return;
	}
	if (psize < 0) {
		trace_perror(trace, "read_packet");
		return;
	}
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
	char srcIP[100];
	if (src_addr_ptr->sa_family == AF_INET) {
		struct sockaddr_in *src_v4 = (struct sockaddr_in *) src_addr_ptr;
		inet_ntop(AF_INET, &(src_v4->sin_addr), srcIP, 100);
	}
	//get destination ip address
	char destIP[100];
	if (dest_addr_ptr->sa_family == AF_INET) {
		struct sockaddr_in *dest_v4 = (struct sockaddr_in *) dest_addr_ptr;
		inet_ntop(AF_INET, &(dest_v4->sin_addr), destIP, 100);
	}
	//fprintf(fp_ip_port, "%s %d %s %d\n", src_ip, src_port, dest_ip, dest_port);

	strcpy(flowEntry->src_ip, srcIP);
	flowEntry->src_port = srcPort;
	strcpy(flowEntry->dest_ip, destIP);
	flowEntry->dest_port = destPort;

	trace_destroy_packet(pkt);
	trace_destroy(trace);
	//fclose(fp_ip_port);

	return 0;
}

