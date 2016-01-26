
CC = gcc
LIBS = -ltrace -lssl -lcrypto
RM = rm

BotTalker: BotTalker.c
	$(CC) -o BotTalker BotTalker.c $(LIBS)

#Packet_Encryption: Packet_Encryption.c
	$(CC) -o Packet_Encryption Packet_Encryption.c $(LIBS)

#Merge_Background_Random: Merge_Background_Random.c
	$(CC) -o Merge_Background_Random Merge_Background_Random.c $(LIBS)

#Flow_Encryption: Flow_Encryption.c
	$(CC) -o Flow_Encryption Flow_Encryption.c $(LIBS)

#Flow_Encryption_SingleFlow: Flow_Encryption_SingleFlow.c
	$(CC) -o Flow_Encryption_SingleFlow Flow_Encryption_SingleFlow.c $(LIBS)

#SSL_Emulation: SSL_Emulation.c
#	$(CC) -o SSL_Emulation SSL_Emulation.c $(LIBS)

#SSL_Emulation_SingleFlow: SSL_Emulation_SingleFlow.c
#	$(CC) -o SSL_Emulation_SingleFlow SSL_Emulation_SingleFlow.c $(LIBS)

#SSL_Extraction_Payload: SSL_Extraction_Payload.c
#	$(CC) -o SSL_Extraction_Payload SSL_Extraction_Payload.c $(LIBS)

#SSL_server: SSL_server.c
#	$(CC) -o SSL_server SSL_server.c $(LIBS)

#SSL_client: SSL_client.c
#	$(CC) -o SSL_client SSL_client.c $(LIBS)

#SSL_Replace_IP: SSL_Replace_IP.c
#	$(CC) -o SSL_Replace_IP SSL_Replace_IP.c $(LIBS)

#GenerateTimestampForSSL: GenerateTimestampForSSL.c
#	$(CC) -o GenerateTimestampForSSL GenerateTimestampForSSL.c $(LIBS)

clean:
	$(RM) BotTalker Packet_Encryption Merge_Background_Random Flow_Encryption Flow_Encryption_SingleFlow
