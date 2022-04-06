#include "parse.h"
#include <iostream>
#include <stdio.h>
#include <openssl/pkcs7.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/err.h>

using namespace std;

void SK_X509_free(stack_st_X509* ptr) {
	sk_X509_free(ptr);
}

using STACK_OF_X509_ptr = std::unique_ptr<STACK_OF(X509), decltype(&SK_X509_free)>;


void OpenSSL_free(void* ptr) {
	OPENSSL_free(ptr);
}

using OpenSSL_ptr = std::unique_ptr<char, decltype(&OpenSSL_free)>;

int main(int argc, char* argv[])
{
	try {
		CertificateParser parser(argv[1]);
		unsigned char* cert_data = nullptr;
		unsigned long cert_lengh = parser.GetCertificate(&cert_data);

		/*FILE* cert_file = fopen(R"(C:\Users\kto\OneDrive - OPSWAT\Desktop\cert.der)", "wb");
		fwrite(cert_data, 1, cert_lengh, cert_file);
		fclose(cert_file);*/

		OpenSSL_add_all_algorithms();
		ERR_load_crypto_strings();

		//https://stackoverflow.com/questions/58065209/get-details-from-pkcs7-cms-via-c
		PKCS7* p7 = d2i_PKCS7(NULL, (const unsigned char **)&cert_data, cert_lengh);

		if (p7 == NULL) {
			unsigned int errCode = ERR_get_error();

			printf("\nError: %s\n", ERR_error_string(errCode, NULL));
			printf("\nLib: %s\n", ERR_lib_error_string(errCode));
			printf("\nFunc: %s\n", ERR_func_error_string(errCode));
			printf("\nReason: %s\n", ERR_reason_error_string(errCode));
			return 0;
		}

		STACK_OF(X509)* certs = NULL;
		int nid = OBJ_obj2nid(p7->type);
		if (nid == NID_pkcs7_signed) {
			certs = p7->d.sign->cert;
		}
		else if (nid == NID_pkcs7_signedAndEnveloped) {
			certs = p7->d.signed_and_enveloped->cert;
		}

		for (int i = 0; certs && i < sk_X509_num(certs); i++) {
			X509* cert = sk_X509_value(certs, i);

			//https://kahdev.wordpress.com/2008/11/23/a-certificates-subject-issuer-and-its-keyusage/
			X509_NAME* subject = X509_get_subject_name(cert);
			BIO* subjectBio = BIO_new(BIO_s_mem());
			X509_NAME_print_ex(subjectBio, subject, 0, XN_FLAG_RFC2253);
			char* dataStart = NULL;
			char* subjectString = NULL;
			long nameLength = BIO_get_mem_data(subjectBio, &dataStart);
			subjectString = new char[nameLength + 1.0];
			memset(subjectString, 0x00, nameLength + 1.0);
			memcpy(subjectString, dataStart, nameLength);
			//std::cout << "Certificate subject name: " << subjectString << std::endl;

			char* cn = new char[256];
			memset(cn, 0, 256);
			//https://stackoverflow.com/questions/15832204/getting-common-name-efficiently-from-tls-certificate-with-openssl
			X509_NAME_get_text_by_NID(subject, NID_commonName, cn, 256);
			//printf("Subject CN: %s\n", cn);
		}

		stack_st_X509 *signers_stack_ptr = PKCS7_get0_signers(p7, nullptr, 0);
		auto signers_stack = STACK_OF_X509_ptr(signers_stack_ptr, SK_X509_free);

		for (auto i = 0; i < sk_X509_num(signers_stack.get()); ++i) {
			X509* cert = sk_X509_value(signers_stack.get(), i);
			auto subject = OpenSSL_ptr(X509_NAME_oneline(X509_get_subject_name(cert), nullptr, 0), OpenSSL_free);
			auto issuer = OpenSSL_ptr(X509_NAME_oneline(X509_get_issuer_name(cert), nullptr, 0), OpenSSL_free);

			std::cout << "Subject: " << std::string(subject.get()) << std::endl;
			std::cout << "Issuer: " << std::string(issuer.get()) << std::endl;
		}

		PKCS7_free(p7);

		// https://tousu.in/qa/?qa=971590/
		/*BIO* in = BIO_new(BIO_s_file());
		BIO* out = BIO_new(BIO_s_file());
		STACK_OF(X509)* certs = NULL;
		int i;
		
		CRYPTO_malloc_init();
		ERR_load_crypto_strings();
		OpenSSL_add_all_algorithms();

		BIO_set_fp(out, stdout, BIO_NOCLOSE);
		BIO_read_filename(in, R"(E:\opswat\Beyond Compare 4\Patch.exe)");
		PKCS7* p7 = d2i_PKCS7_bio(in, NULL);

		i = OBJ_obj2nid(p7->type);
		if (i == NID_pkcs7_signed) {
			certs = p7->d.sign->cert;
		}
		else if (i == NID_pkcs7_signedAndEnveloped) {
			certs = p7->d.signed_and_enveloped->cert;
		}

		for (i = 0; certs && i < sk_X509_num(certs); i++) {
			X509* x = sk_X509_value(certs, i);
			PEM_write_bio_X509(out, x);
		}*/
	}
	catch (std::string &e) {
	}
	
	return 0;
}