#include "common.h"

void handle_error(const char *file, int lineno, const char *msg)
{
	fprintf(stderr, "** %s:%i %s\n", file, lineno, msg);
	ERR_print_errors_fp(stderr);
	exit(-1);
}

void init_OpenSSL(void)
{
	//if (!THREAD_setup() || ! SSL_library_init())
	if (! SSL_library_init())
	{
		fprintf(stderr, "** OpenSSL initialization failed!\n");
		exit(-1);
	}
	SSL_load_error_strings();
}

int verify_callback(int ok, X509_STORE_CTX *store)
{
	char data[256];
	if (!ok)
	{
		X509 *cert = X509_STORE_CTX_get_current_cert(store);
		int depth = X509_STORE_CTX_get_error_depth(store);
		int err = X509_STORE_CTX_get_error(store);
		
		fprintf(stderr, "-Error with certificate at depth: %i\n", depth);
		
		X509_NAME_oneline(X509_get_issuer_name(cert), data, 256);
		fprintf(stderr, " issuer = %s\n", data);
		X509_NAME_oneline(X509_get_subject_name(cert), data, 256);
		fprintf(stderr, " subject = %s\n", data); 
		fprintf(stderr, " err %i:%s\n", err, X509_verify_cert_error_string(err));
	}
	return ok;
}
