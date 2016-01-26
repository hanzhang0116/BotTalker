
Introduction:
	BotTalker emulates the actions a bot would take to encrypt communication and produces traces that look like they come from real botnets. BotTalker is able to convert non-encrypted botnet traces into encrypted ones. It enables customization along three dimensions: (a) selection of real encryption algorithm, (b) flow or packet level conversion, SSL emulation and (c) IP address substitution. More details can be found in our published paper - [BotTalker] (http://www.cs.colostate.edu/~hanzhang/papers/BotTalker.pdf).

Installation:
	Install required libraries:
		libpcap (e.g., sudo yum install libpcap)
		libpcap-devel
		libtrace
		openssl
		openssl-devel
		bison
		flex
		wireshark
	Compile:
		make
	Run:
		./BotTalker with options listed as follows

Supported Encryption Scheme:
	These encryption schemes can be specified using option '-P', '-F'.
	Packet level emulation: emulate the case where a bot encrypts packets individually as they are transmitted.
	Flow level emulation: emulate the case where a bot transmits encrypted objects.
	SSL emulation (supported soon): emulate the case when the botnet exchange information via SSL connections.

Supported Encryption Algorithm:
	These encryption algorithms can be specified using option '-e', for example, '-e xor', '-e EVP_des_cbc'
	xor:		xor
	des: 		EVP_des_cbc, EVP_des_ecb, EVP_des_cfb, EVP_des_ofb
	des 2 key:	EVP_des_ede_cbc, EVP_des_ede, EVP_des_ede_ofb, EVP_des_ede_cfb
	des 3 key:	EVP_des_ede3_cbc, EVP_des_ede3, EVP_des_ede3_ofb, EVP_des_ede3_cfb
	desx: 		EVP_desx_cbc
	rc4:		EVP_rc4
	rc4 40 bit key:	EVP_rc4_40
	rc2:		EVP_rc2_cbc, EVP_rc2_ecb, EVP_rc2_cfb, EVP_rc2_ofb, EVP_rc2_40_cbc, EVP_rc2_64_cbc
	Blowfish: 	EVP_bf_cbc, EVP_bf_ecb, EVP_bf_cfb, EVP_bf_ofb
	CAST:		EVP_cast5_cbc, EVP_cast5_ecb, EVP_cast5_cfb, EVP_cast5_ofb
	AES:		EVP_aes_128_ecb, EVP_aes_128_cbc, EVP_aes_192_ecb, EVP_aes_192_cbc, EVP_aes_256_ecb, EVP_aes_256_cbc

Options:
	-a: specify the file including IPs that do not need to replaced when option -r is used
	-b:	specify background traffic
	-c: specify configuration file
	-d: specify the file including ports whose traffic will not be encrypted when option -P or -F is used. For example, we may want to encrypt all the traffic except DNS (port 53). A file named portExclusionFile is given in the package as an example.
	-e:	specify encryption algorithm
	-f:	specify the flow to encrypt. E.g. -f all, or -f flowsToEncryptFiles
		format of flowsToEncryptFiles: srcIP, srcPort, destIP, destPort, Proto
		A file named flowsEncryption is given in the package as an example.
	-k: specify encryption key and iv file
		A file named keyProfile is given in the package as an example.
	-i:	specify input trace
	-o:	specify output trace
	-r:	apply ip replacement, followed by the ip pair. E.g. -r '192.168.9.5/24 178.162.181.84/24'
	-n: replace a single IP address.
		option '-r' and '/32' need to be given (e.g., -n -r '192.168.9.5/32 178.162.181.84/32')
	-N: replace a subnet of IP addresses.
		option '-r' needs to be given (e.g., -n -r '192.168.9.5/24 178.162.181.84/24')
	-l: specify background traffic local network. E.g. -l '129.82.138.0/24'
	-t:	specify time adjustment (e.g., 300, -10)
	-M:	specify traffic merge scheme. 
		Two schemes are support:
		1. direct: -M 'direct' merge the background traffic with botnet traffic directly
		2. random selection: random select hosts in background traffic and assign botnet traffic on them -M '192.168.9.0'
	-P:	enable packet level encryption
	-F:	enable flow level encryption
	-h:	display this help and exit

Example:
	./BotTalker -i testInput.pcap -o testOutput.pcap -k keyProfile -e xor -f all -P -r '192.168.1.5/32 111.11.111.1/32' -n
	-i: the input pcap file is testInput.pcap
	-o: the output pcap file is testOutput.pcap
	-k: the key and iv is given in file keyProfile
	-e: encrypt the payload using xor
	-f: encrypt all the packets
	-P: use packet level encryption
	-r, -n: replace IP 192.168.1.5 with 111.11.111.1

	./BotTalker -i botnet.pcap -o botnetBackgroundMix.pcap -e EVP_des_cbc -k keyProfile -f flowsEncryption -F -b background.pcap -l '192.168.0.0/16' -t 1200 -M '192.168.9.0/24'
	-i: the input botnet pcap file is botnet.pcap
	-o: the output pcap file is botnetBackgroundMix.pcap
	-k: the key and iv is given in file keyProfile
	-e: encrypt the payload using des: EVP_des_cbc
	-f: encrypt the packets belonging to flows in file flowsEncryption
	-F: use flow level encryption (highly recommend not to encrypt all the flows when using flow level encryption due to performance issues)
	-l: the local network of the background trace is '192.168.0.0/16'
	-t: adjust the timestamp 1200 seconds forward
	-M: randomly select hosts in the background trace in subnet '192.168.9.0/24' and add the bot traffic on them (the bots' IPs will also be changed).



