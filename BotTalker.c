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
#include <libtrace.h>
#include <stdio.h> 
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include "BotTalkerFunctions.c"

struct config_parameters configBottalker;

int main(int argc, char *argv[])
{
	int opt = 0;
	int enableEncryption = 0;		//1 means the data needs to be encrypted
	int enableKeyIV = 0;
	int encryptAll = 0;		//encrypt all the traffic, otherwise encrypt a specific flow
	int enableEncryptExecutable = 0;	//1 means use the executable magic number files
	int enableReplaceIP = 0;		//apply IP replacement
	int enableBackgroundFile = 0;
	int enableBotnetNetwork = 0;
	int enableInputFile = 0;
	int enableOutputFile = 0;
	int enableLocalNetwork = 0;
	int enableEncryptionFlows = 0;
	int enableTimeAdjust = 0;
	int enablePacketLevel = 0;
	int enableFlowLevel = 0;
	int enableMergeScheme = 0;
	int enableSSLEmulation = 0;
	int enableIPExclusion = 0;
	int enablePortExclusion = 0;
	int enableReplaceCertainIP = 0;
	int enableReplaceAllIP = 0;
	char oriInputFile[MAX_SIZE];
	char oriOutputFile[MAX_SIZE];
	char backgroundFile[MAX_SIZE];
	char botnetNetwork[MAX_SIZE];
	char localNetwork[MAX_SIZE];
	char encryptionFlows[MAX_SIZE];
	char timeAdjust[MAX_SIZE];
	char encryption[MAX_SIZE];
	char inputFile[MAX_SIZE];
	char outputFile[MAX_SIZE];
	char keyIVFile[MAX_SIZE];
	char ipExclusionFile[MAX_SIZE];
	char portExclusionFile[MAX_SIZE];
	char configFile[MAX_SIZE];
	char encryptionAlgorithm[16];
	char exeMagicNumberFile[MAX_SIZE];
	char oriReplaceIP[MAX_SIZE];
	char mergeScheme[MAX_SIZE];
	char command[MAX_SIZE];

	if ((argc - optind) < 1) {
		usage();
		exit(1);
	}

	while ((opt = getopt(argc, argv, "a:b:c:d:e:f:Fk:l:i:o:Pr:M:nNSt:")) !=-1)
	{
		switch (opt)
		{
			case 'a':
				strcpy(ipExclusionFile, optarg);
				enableIPExclusion = 1;
				break;
			case 'b':
				strcpy(backgroundFile, optarg);
				enableBackgroundFile = 1;
				break;
			case 'c':
				strcpy(configFile, optarg);
				break;
			case 'd':
				strcpy(portExclusionFile, optarg);
				enablePortExclusion = 1;
				break;
			case 'M':
				strcpy(mergeScheme, optarg);
				enableMergeScheme = 1;
				break;
			case 'i':
				strcpy(inputFile, optarg);
				enableInputFile = 1;
				break;
			case 'l':
				strcpy(localNetwork, optarg);
				enableLocalNetwork = 1;
				break;
			case 'o':
				strcpy(outputFile, optarg);
				enableOutputFile = 1;
				break;
			case 'k':
				strcpy(keyIVFile, optarg);
				enableKeyIV = 1;
				break;
			case 'e':
				strcpy(encryptionAlgorithm, optarg);
				enableEncryption = 1;
				break;
			case 'f':
				/*encrypt all the traffic*/
				strcpy(encryptionFlows, optarg);
				enableEncryptionFlows = 1;
				break;
			case 'F':
				enableFlowLevel = 1;
				break;
			case 'P':
				enablePacketLevel = 1;
				break;
			case 'S':
				enableSSLEmulation = 1;
				break;
			case 'r':
				strcpy(oriReplaceIP, optarg);
				enableReplaceIP = 1;
				break;
			case 'n':
				enableReplaceCertainIP = 1;
				break;
			case 'N':
				enableReplaceAllIP = 1;
				break;
			case 't':
				strcpy(timeAdjust, optarg);
				enableTimeAdjust = 1;
				break;
			case 'h':
				usage();
				exit(1);
			default:
				usage();
				exit(1);
		}
	}

	//reserved for SSL emulation
	/*
	ReadConfigurationFile(configFile, &configBottalker);
	printf("MERGECAP: %s\n", configBottalker.COMMAND_MERGECAP);
	printf("EDITCAP: %s\n", configBottalker.COMMAND_EDITCAP);
	printf("CIPHER_LIST: %s\n", configBottalker.CIPHER_LIST);
	printf("CAFILE: %s\n", configBottalker.CAFILE);
	printf("CERTFILE: %s\n", configBottalker.CERTFILE);
	printf("PORT: %s\n", configBottalker.PORT);
	printf("SERVER: %s\n", configBottalker.SERVER);
	printf("CLIENT: %s\n", configBottalker.CLIENT);
	*/

	if( ((enablePacketLevel == 1) || (enableFlowLevel == 1)) && ((enableEncryption == 1) || (enableEncryptionFlows == 1) || (enableKeyIV == 1) ))
	{
		if(enableEncryption + enableEncryptionFlows + enableKeyIV < 3)
		{
			printf("-e -f -k need to be used together\n");
			exit(1);
		}
	}

	if( (enableBackgroundFile == 1) || (enableLocalNetwork == 1) || (enableTimeAdjust == 1) || (enableMergeScheme == 1) )
	{
		if(enableBackgroundFile + enableLocalNetwork + enableMergeScheme < 3)
		{
			printf("-l -b -M need to be used together\n");
			exit(1);
		}
	}
	if( enablePacketLevel + enableFlowLevel + enableSSLEmulation > 1 )
	{
		printf("Can not apply more than one of packet level encryption, flow level encryption, or ssl emulation at the same time\n");
		exit(1);
	}

	strcpy(oriOutputFile, outputFile);
	strcpy(oriInputFile, inputFile);
	if( (enableBackgroundFile == 1) && ( (enableEncryption == 1) || (enableReplaceIP == 1) ) )
	{
		sprintf(outputFile, "%s-encryption", oriOutputFile);
	}
	memset(command, '\0', sizeof(command));
	if(enablePacketLevel == 1)
	{
		sprintf(command, "./Packet_Encryption -i pcap:%s -o pcap:%s", inputFile, outputFile);
	}
	else if(enableFlowLevel == 1)
	{
		sprintf(command, "./Flow_Encryption -i %s -o %s", inputFile, outputFile);
	}

	//reserved for SSL emulation
	/*
	else if(enableSSLEmulation == 1)
	{
		sprintf(command, "sudo ./SSL_Emulation -i %s -o %s -f '%s' -c %s", inputFile, outputFile, encryptionFlows, configFile);
		if(enablePortExclusion == 1)
		{
			sprintf(command, "%s -d %s", command, portExclusionFile);
		}
		printf("command: %s\n", command);
		system(command);
		return;
	}
	*/

	/*Concatenate the encryption algorithm and key IV*/
	if(enableEncryption == 1)
	{
		sprintf(command, "%s -e %s -k %s -f %s", command, encryptionAlgorithm, keyIVFile, encryptionFlows);
	}

	/*concatenate the IP replacement*/
	if(enableReplaceIP == 1)
	{
		sprintf(command, "%s -r '%s'", command, oriReplaceIP);
	}

	if(enableIPExclusion == 1)
	{
		sprintf(command, "%s -a %s", command, ipExclusionFile);
	}
	if(enablePortExclusion == 1)
	{
		sprintf(command, "%s -d %s", command, portExclusionFile);
	}
	if(enableReplaceCertainIP == 1)
	{
		sprintf(command, "%s -n", command);
	}
	if(enableReplaceAllIP == 1)
	{
		sprintf(command, "%s -N", command);
	}
	printf("command: %s\n", command);
	system(command);

	memset(command, '\0', sizeof(command));
	memset(inputFile, '\0', sizeof(inputFile));
	memset(outputFile, '\0', sizeof(outputFile));
	if( (enableBackgroundFile == 1) && ( (enableEncryption == 1) || (enableReplaceIP == 1) ) )
	{
		sprintf(inputFile, "%s-encryption", oriOutputFile);
	}
	else
	{
		sprintf(inputFile, "%s", oriOutputFile);
	}
	strcpy(outputFile, oriOutputFile);

	/*adjust timestamps*/
	if(enableTimeAdjust == 1)
	{
		sprintf(outputFile, "%s-time-adjust", oriOutputFile);
		sprintf(command, "editcap -t %s %s %s -F pcap", timeAdjust, inputFile, outputFile);
		strcpy(inputFile, outputFile);
		strcpy(outputFile, oriOutputFile);
		printf("command: %s\n", command);
		system(command);
	}

	/*merge with background traffic*/
	if(enableBackgroundFile == 1)
	{
		memset(outputFile, '\0', sizeof(outputFile));
		strcpy(outputFile, oriOutputFile);
		printf("outputFile: %s\n", outputFile);
		/*merge the bot traffic directly with background hosts' traffic*/
		if(strcmp(mergeScheme, "direct") == 0)
		{
			sprintf(command, "mergecap pcap:%s pcap:%s -w pcap:%s -F pcap", inputFile, backgroundFile, outputFile);
			printf("command: %s\n", command);
			system(command);
		}
		/*add bot traffic on randomly selected hosts from background traffic*/
		else
		{
			//sprintf(command, "./Merge_Background_Random -i pcap:%s -o pcap:%s-temp -b pcap:%s -l '%s' -M '%s'", inputFile, outputFile, backgroundFile, localNetwork, mergeScheme);
			sprintf(command, "./Merge_Background_Random -i pcap:%s -o pcap:%s -b pcap:%s -l '%s' -M '%s'", inputFile, outputFile, backgroundFile, localNetwork, mergeScheme);
			printf("command: %s\n", command);
			system(command);
			memset(command, '\0', sizeof(command));
		}
	}
	return 0;
}
