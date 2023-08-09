#include "parse.h"
#include <iostream>
#include <algorithm>
#include <array>
#include <stdio.h>
#include <openssl/pkcs7.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/asn1.h>
#include <openssl/cms.h>
#include <openssl/asn1t.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/bn.h>
#include "jwt-cpp/jwt.h"

using namespace std;

void SK_X509_free(stack_st_X509* ptr) {
	sk_X509_free(ptr);
}

using STACK_OF_X509_ptr = std::unique_ptr<STACK_OF(X509), decltype(&SK_X509_free)>;


void OpenSSL_free(void* ptr) {
	OPENSSL_free(ptr);
}

using OpenSSL_ptr = std::unique_ptr<char, decltype(&OpenSSL_free)>;

/* Microsoft OID Authenticode */
#define SPC_INDIRECT_DATA_OBJID      "1.3.6.1.4.1.311.2.1.4"
#define SPC_STATEMENT_TYPE_OBJID     "1.3.6.1.4.1.311.2.1.11"
#define SPC_SP_OPUS_INFO_OBJID       "1.3.6.1.4.1.311.2.1.12"
#define SPC_PE_IMAGE_DATA_OBJID      "1.3.6.1.4.1.311.2.1.15"
#define SPC_CAB_DATA_OBJID           "1.3.6.1.4.1.311.2.1.25"
#define SPC_SIPINFO_OBJID            "1.3.6.1.4.1.311.2.1.30"
#define SPC_PE_IMAGE_PAGE_HASHES_V1  "1.3.6.1.4.1.311.2.3.1" /* SHA1 */
#define SPC_PE_IMAGE_PAGE_HASHES_V2  "1.3.6.1.4.1.311.2.3.2" /* SHA256 */
#define SPC_NESTED_SIGNATURE_OBJID   "1.3.6.1.4.1.311.2.4.1"
/* Microsoft OID Time Stamping */
#define SPC_TIME_STAMP_REQUEST_OBJID "1.3.6.1.4.1.311.3.2.1"
#define SPC_RFC3161_OBJID            "1.3.6.1.4.1.311.3.3.1"
/* Microsoft OID Crypto 2.0 */
#define MS_CTL_OBJID                 "1.3.6.1.4.1.311.10.1"
/* Microsoft OID Microsoft_Java */
#define MS_JAVA_SOMETHING            "1.3.6.1.4.1.311.15.1"

/* Public Key Cryptography Standards PKCS#9 */
#define PKCS9_MESSAGE_DIGEST         "1.2.840.113549.1.9.4"
#define PKCS9_SIGNING_TIME           "1.2.840.113549.1.9.5"
#define PKCS9_COUNTER_SIGNATURE      "1.2.840.113549.1.9.6"

#define CONTENT_TYPE_OBJID			 "1.2.840.113549.1.9.3"

static int asn1_print_time(const ASN1_TIME* time)
{
	BIO* bp;

	if ((time == NULL) || (!ASN1_TIME_check(time))) {
		printf("N/A\n");
		return 0; /* FAILED */
	}
	bp = BIO_new_fp(stdout, BIO_NOCLOSE);
	ASN1_TIME_print(bp, time);
	BIO_free(bp);
	printf("\n");
	return 1; /* OK */
}
#include <iostream>
#include <sstream>

#define MAX_NAME_LENGTH 256

void getDetails(PKCS7* p7)
{
	STACK_OF(X509)* signers_stack_ptr = PKCS7_get0_signers(p7, nullptr, 0);
	auto cert = sk_X509_value(signers_stack_ptr, 0);

	std::array<char, MAX_NAME_LENGTH> subject;
	X509_NAME_get_text_by_NID(X509_get_subject_name(cert), NID_commonName, subject.data(), MAX_NAME_LENGTH);

	std::array<char, MAX_NAME_LENGTH> issuer;
	X509_NAME_get_text_by_NID(X509_get_issuer_name(cert), NID_commonName, issuer.data(), MAX_NAME_LENGTH);

	printf("\n---- KHAI ---- %s\n", subject.data());

	BIGNUM* serialbn = ASN1_INTEGER_to_BN(X509_get_serialNumber(cert), nullptr);
	char* serial = BN_bn2hex(serialbn);


	sk_X509_free(signers_stack_ptr);
	BN_free(serialbn);
	// Since function BN_bn2hex uses 'malloc' to allocate memory so we must use 'OPENSSL_free' to release memory
	OPENSSL_free(serial);
}

static int print_cert(X509* cert, int i)
{
	char* subject, * issuer, * serial;
	BIGNUM* serialbn;

	subject = X509_NAME_oneline(X509_get_subject_name(cert), NULL, 0);
	issuer = X509_NAME_oneline(X509_get_issuer_name(cert), NULL, 0);
	serialbn = ASN1_INTEGER_to_BN(X509_get_serialNumber(cert), NULL);
	serial = BN_bn2hex(serialbn);
	long version = X509_get_version(cert);
	if (i > 0)
		printf("\t------------------\n");
	printf("\tSigner #%d:\n\t\tVersion: %d\n\t\tSubject: %s\n\t\tIssuer : %s\n\t\tSerial : %s\n\t\tCertificate expiration date:\n",
		i, version, subject, issuer, serial);
	printf("\t\t\tnotBefore : ");
	asn1_print_time(X509_get0_notBefore(cert));
	printf("\t\t\tnotAfter : ");
	asn1_print_time(X509_get0_notAfter(cert));

	OPENSSL_free(subject);
	OPENSSL_free(issuer);
	BN_free(serialbn);
	OPENSSL_free(serial);
	
	return 1; /* OK */
}

#define INVALID_TIME ((time_t)-1)

static time_t asn1_get_time_t(const ASN1_TIME* s)
{
	struct tm tm;

	if ((s == NULL) || (!ASN1_TIME_check(s))) {
		return INVALID_TIME;
	}
	if (ASN1_TIME_to_tm(s, &tm)) {
		return mktime(&tm);
	}
	else {
		return INVALID_TIME;
	}
}

static int print_time_t(const time_t time)
{
	ASN1_TIME* s;
	int ret;

	if (time == INVALID_TIME) {
		printf("N/A\n");
		return 0; /* FAILED */
	}
	if ((s = ASN1_TIME_set(NULL, time)) == NULL) {
		printf("N/A\n");
		return 0; /* FAILED */
	}
	ret = asn1_print_time(s);
	ASN1_TIME_free(s);
	return ret;

}

static void tohex(const unsigned char* v, char* b, int len)
{
	int i, j = 0;
	for (i = 0; i < len; i++) {
#ifdef WIN32
		int size = EVP_MAX_MD_SIZE * 2 + 1;
		j += sprintf_s(b + j, size - j, "%02X", v[i]);
#else
		j += sprintf(b + j, "%02X", v[i]);
#endif /* WIN32 */
	}
}

void print_hash(char* descript1, char* descript2, unsigned char* hashbuf, int length)
{
	char hexbuf[EVP_MAX_MD_SIZE * 2 + 1];

	if (length > EVP_MAX_MD_SIZE) {
		printf("Invalid message digest size\n");
		return;
	}
	tohex(hashbuf, hexbuf, length);
	printf("%s: %s %s\n", descript1, hexbuf, descript2);
}

static time_t si_get_time(PKCS7_SIGNER_INFO* si)
{
	STACK_OF(X509_ATTRIBUTE)* auth_attr;
	X509_ATTRIBUTE* attr;
	ASN1_OBJECT* object;
	ASN1_UTCTIME* time = NULL;
	time_t posix_time;
	char object_txt[128];
	int i;

	auth_attr = PKCS7_get_signed_attributes(si);  /* cont[0] */
	if (auth_attr)
		for (i = 0; i < X509at_get_attr_count(auth_attr); i++) {
			attr = X509at_get_attr(auth_attr, i);
			object = X509_ATTRIBUTE_get0_object(attr);
			if (object == NULL)
				return INVALID_TIME; /* FAILED */
			object_txt[0] = 0x00;
			OBJ_obj2txt(object_txt, sizeof object_txt, object, 1);
			if (!strcmp(object_txt, PKCS9_SIGNING_TIME)) {
				/* PKCS#9 signing time - Policy OID: 1.2.840.113549.1.9.5 */
				time = static_cast<ASN1_UTCTIME*>(X509_ATTRIBUTE_get0_data(attr, 0, V_ASN1_UTCTIME, NULL));
			}
		}
	posix_time = asn1_get_time_t(time);
	return posix_time;
}

typedef struct {
	ASN1_OBJECT* algorithm;
	ASN1_TYPE* parameters;
} AlgorithmIdentifier;

DECLARE_ASN1_FUNCTIONS(AlgorithmIdentifier)

ASN1_SEQUENCE(AlgorithmIdentifier) = {
	ASN1_SIMPLE(AlgorithmIdentifier, algorithm, ASN1_OBJECT),
	ASN1_OPT(AlgorithmIdentifier, parameters, ASN1_ANY)
} ASN1_SEQUENCE_END(AlgorithmIdentifier)

IMPLEMENT_ASN1_FUNCTIONS(AlgorithmIdentifier)


typedef struct {
	AlgorithmIdentifier* digestAlgorithm;
	ASN1_OCTET_STRING* digest;
} MessageImprint;

DECLARE_ASN1_FUNCTIONS(MessageImprint)

ASN1_SEQUENCE(MessageImprint) = {
	ASN1_SIMPLE(MessageImprint, digestAlgorithm, AlgorithmIdentifier),
	ASN1_SIMPLE(MessageImprint, digest, ASN1_OCTET_STRING)
} ASN1_SEQUENCE_END(MessageImprint)

IMPLEMENT_ASN1_FUNCTIONS(MessageImprint)

typedef struct {
	ASN1_INTEGER* seconds;
	ASN1_INTEGER* millis;
	ASN1_INTEGER* micros;
} TimeStampAccuracy;

DECLARE_ASN1_FUNCTIONS(TimeStampAccuracy)

ASN1_SEQUENCE(TimeStampAccuracy) = {
	ASN1_OPT(TimeStampAccuracy, seconds, ASN1_INTEGER),
	ASN1_IMP_OPT(TimeStampAccuracy, millis, ASN1_INTEGER, 0),
	ASN1_IMP_OPT(TimeStampAccuracy, micros, ASN1_INTEGER, 1)
} ASN1_SEQUENCE_END(TimeStampAccuracy)

IMPLEMENT_ASN1_FUNCTIONS(TimeStampAccuracy)

typedef struct {
	ASN1_INTEGER* version;
	ASN1_OBJECT* policy_id;
	MessageImprint* messageImprint;
	ASN1_INTEGER* serial;
	ASN1_GENERALIZEDTIME* time;
	TimeStampAccuracy* accuracy;
	ASN1_BOOLEAN ordering;
	ASN1_INTEGER* nonce;
	GENERAL_NAME* tsa;
	STACK_OF(X509_EXTENSION)* extensions;
} TimeStampToken;

DECLARE_ASN1_FUNCTIONS(TimeStampToken)

ASN1_SEQUENCE(TimeStampToken) = {
	ASN1_SIMPLE(TimeStampToken, version, ASN1_INTEGER),
	ASN1_SIMPLE(TimeStampToken, policy_id, ASN1_OBJECT),
	ASN1_SIMPLE(TimeStampToken, messageImprint, MessageImprint),
	ASN1_SIMPLE(TimeStampToken, serial, ASN1_INTEGER),
	ASN1_SIMPLE(TimeStampToken, time, ASN1_GENERALIZEDTIME),
	ASN1_OPT(TimeStampToken, accuracy, TimeStampAccuracy),
	ASN1_OPT(TimeStampToken, ordering, ASN1_FBOOLEAN),
	ASN1_OPT(TimeStampToken, nonce, ASN1_INTEGER),
	ASN1_EXP_OPT(TimeStampToken, tsa, GENERAL_NAME, 0),
	ASN1_IMP_SEQUENCE_OF_OPT(TimeStampToken, extensions, X509_EXTENSION, 1)
} ASN1_SEQUENCE_END(TimeStampToken)

IMPLEMENT_ASN1_FUNCTIONS(TimeStampToken)

typedef struct {
	ASN1_OBJECT* type;
	ASN1_TYPE* value;
} SpcAttributeTypeAndOptionalValue;

DECLARE_ASN1_FUNCTIONS(SpcAttributeTypeAndOptionalValue)

ASN1_SEQUENCE(SpcAttributeTypeAndOptionalValue) = {
	ASN1_SIMPLE(SpcAttributeTypeAndOptionalValue, type, ASN1_OBJECT),
	ASN1_OPT(SpcAttributeTypeAndOptionalValue, value, ASN1_ANY)
} ASN1_SEQUENCE_END(SpcAttributeTypeAndOptionalValue)

IMPLEMENT_ASN1_FUNCTIONS(SpcAttributeTypeAndOptionalValue)

typedef struct {
	AlgorithmIdentifier* digestAlgorithm;
	ASN1_OCTET_STRING* digest;
} DigestInfo;

DECLARE_ASN1_FUNCTIONS(DigestInfo)

ASN1_SEQUENCE(DigestInfo) = {
	ASN1_SIMPLE(DigestInfo, digestAlgorithm, AlgorithmIdentifier),
	ASN1_SIMPLE(DigestInfo, digest, ASN1_OCTET_STRING)
} ASN1_SEQUENCE_END(DigestInfo)

IMPLEMENT_ASN1_FUNCTIONS(DigestInfo)

typedef struct {
	SpcAttributeTypeAndOptionalValue* data;
	DigestInfo* messageDigest;
} SpcIndirectDataContent;

DECLARE_ASN1_FUNCTIONS(SpcIndirectDataContent)

ASN1_SEQUENCE(SpcIndirectDataContent) = {
	ASN1_SIMPLE(SpcIndirectDataContent, data, SpcAttributeTypeAndOptionalValue),
	ASN1_SIMPLE(SpcIndirectDataContent, messageDigest, DigestInfo)
} ASN1_SEQUENCE_END(SpcIndirectDataContent)

IMPLEMENT_ASN1_FUNCTIONS(SpcIndirectDataContent)

static time_t cms_get_time(CMS_ContentInfo* cms)
{
	ASN1_OCTET_STRING** pos;
	const unsigned char* p = NULL;
	TimeStampToken* token = NULL;
	ASN1_GENERALIZEDTIME* asn1_time = NULL;
	time_t posix_time = INVALID_TIME;

	pos = CMS_get0_content(cms);
	if (pos != NULL && *pos != NULL) {
		p = (*pos)->data;
		token = d2i_TimeStampToken(NULL, &p, (*pos)->length);
		if (token) {
			asn1_time = token->time;
			posix_time = asn1_get_time_t(asn1_time);
			TimeStampToken_free(token);
		}
	}
	return posix_time;
}

static void* get_oid_data_from_asn1_internal(const uint8_t* buf, size_t buf_len, const void* oid,
	size_t oid_len, uint8_t asn1_type, size_t* data_len, bool* matched)
{
	void* ret;
	size_t pos = 0, len, len_len, i;
	uint8_t tag;
	bool is_sequence;

	while (pos < buf_len) {
		is_sequence = buf[pos] & 0x20;	// Only need to handle the sequence attribute
		tag = buf[pos++] & 0x1F;

		// Compute the length
		len = 0;
		len_len = 1;
		if (tag == 0x05) {	// ignore "NULL" tag
			pos++;
		}
		else {
			if (buf[pos] & 0x80) {
				len_len = buf[pos++] & 0x7F;
				// The data we're dealing with is not expected to ever be larger than 64K
				if (len_len > 2) {
					printf("get_oid_data_from_asn1: Length fields larger than 2 bytes are unsupported");
					return NULL;
				}
				for (i = 0; i < len_len; i++) {
					len <<= 8;
					len += buf[pos++];
				}
			}
			else {
				len = buf[pos++];
			}

			if (len > buf_len - pos) {
				printf("get_oid_data_from_asn1: Overflow error (computed length %ud is larger than remaining data)", len);
				return NULL;
			}
		}

		if (len != 0) {
			if (is_sequence) {
				ret = get_oid_data_from_asn1_internal(&buf[pos], len, oid, oid_len, asn1_type, data_len, matched);
				if (ret != NULL)
					return ret;
			}
			else {
				// NB: 0x06 = "OID" tag
				if ((!*matched) && (tag == 0x06) && (len == oid_len) && (memcmp(&buf[pos], oid, oid_len) == 0)) {
					*matched = true;
				}
				else if ((*matched) && (tag == asn1_type)) {
					*data_len = len;
					return (void*)&buf[pos];
				}
			}
			pos += len;
		}
	};

	return NULL;
}

void* get_oid_data_from_asn1(const uint8_t* buf, size_t buf_len, const uint8_t* oid, size_t oid_len,
	uint8_t asn1_type, size_t* data_len)
{
	bool matched = (oid == NULL);
	return get_oid_data_from_asn1_internal(buf, buf_len, oid, oid_len, asn1_type, data_len, &matched);
}

static void cms_get_time_1(const unsigned char* data, int len)
{
	const uint8_t OID_RFC3161_timeStamp[] = { 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x10, 0x01, 0x04 };
	size_t timestamp_token_size;

	uint8_t* timestamp_token = static_cast<uint8_t*>(get_oid_data_from_asn1(data, len, OID_RFC3161_timeStamp, sizeof(OID_RFC3161_timeStamp),
		// 0x04 = "Octet String" ASN.1 tag
		0x04, &timestamp_token_size));

	if (timestamp_token) {
		char* timestamp_str;
		size_t timestamp_str_size;
		timestamp_str = static_cast<char*>(get_oid_data_from_asn1(timestamp_token, timestamp_token_size, NULL, 0,
			// 0x18 = "Generalized Time" ASN.1 tag
			0x18, &timestamp_str_size));
		if (timestamp_str) {
			uint64_t ts = strtoull(timestamp_str, NULL, 10);
			std::cout << "----------------------" << ts << "--------------------\n";
		}
	}
}

unsigned char* base64_decode(const char* base64data, int* len) {
	BIO* b64, * bmem;
	size_t length = strlen(base64data);
	unsigned char* buffer = (unsigned char*)malloc(length);
	b64 = BIO_new(BIO_f_base64());
	BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
	bmem = BIO_new_mem_buf((void*)base64data, length);
	bmem = BIO_push(b64, bmem);
	*len = BIO_read(bmem, buffer, length);
	BIO_free_all(bmem);
	return buffer;
}

BIGNUM* bignum_base64_decode(const char* base64bignum) {
	BIGNUM* bn = NULL;
	int len;
	unsigned char* data = base64_decode(base64bignum, &len);
	if (len) {
		bn = BN_bin2bn(data, len, NULL);
	}
	free(data);
	return bn;
}

EVP_PKEY* RSA_fromBase64(const char* modulus_b64, const char* exp_b64) {
	BIGNUM* n = bignum_base64_decode(modulus_b64);
	BIGNUM* e = bignum_base64_decode(exp_b64);

	if (!n) printf("Invalid encoding for modulus\n");
	if (!e) printf("Invalid encoding for public exponent\n");

	if (e && n) {
		EVP_PKEY* pRsaKey = EVP_PKEY_new();
		RSA* rsa = RSA_new();
		RSA_set0_key(rsa, n, e, NULL);
		EVP_PKEY_assign_RSA(pRsaKey, rsa);
		return pRsaKey;
	}
	else {
		if (n) BN_free(n);
		if (e) BN_free(e);
		return NULL;
	}
}

void decode(std::string &s) {
	//s = s.replace('-', '+'); // 62nd char of encoding
	//s = s.Replace('_', '/'); // 63rd char of encoding

	std::replace(s.begin(), s.end(), '-', '+');
	std::replace(s.begin(), s.end(), '_', '/');

	switch (strlen(s.c_str()) % 4) // Pad with trailing '='s
	{
	case 0: break; // No pad chars in this case
	case 2: s += "=="; break; // Two pad chars
	case 3: s += "="; break; // One pad char
	default: fprintf(stderr, "Illegal base64url string!");
	}
}

int main(int argc, char* argv[])
{
	/*const char* modulus = "tJL6Wr2JUsxLyNezPQh1J6zn6wSoDAhgRYSDkaMuEHy75VikiB8wg25WuR96gdMpookdlRvh7SnRvtjQN9b5m4zJCMpSRcJ5DuXl4mcd7Cg3Zp1C5-JmMq8J7m7OS9HpUQbA1yhtCHqP7XA4UnQI28J-TnGiAa3viPLlq0663Cq6hQw7jYo5yNjdJcV5-FS-xNV7UHR4zAMRruMUHxte1IZJzbJmxjKoEjJwDTtcd6DkI3yrkmYt8GdQmu0YBHTJSZiz-M10CY3LbvLzf-tbBNKQ_gfnGGKF7MvRCmPA_YF_APynrIG7p4vPDRXhpG3_CIt317NyvGoIwiv0At83kQ";
	const char* exp = "AQAB";

	std::string n = std::string(modulus);
	std::string e = std::string(exp);

	decode(n);
	decode(e);

	EVP_PKEY* pkey = RSA_fromBase64(n.c_str(), e.c_str());

	if (pkey == NULL) {
		fprintf(stderr, "an error occurred :(\n");
		return 2;
	}
	else {
		printf("success decoded into RSA public key\n");
		BIO* bio = BIO_new(BIO_s_mem());;
		PEM_write_bio_PUBKEY(bio, pkey);
		char* ptr = (char*)malloc(BIO_number_written(bio) + 1);
		if (NULL == ptr) {
			BIO_free(bio);
			return NULL;
		}
		memset(ptr, 0, BIO_number_written(bio) + 1);
		BIO_read(bio, ptr, BIO_number_written(bio));
		BIO_free(bio);
		std::cout << ptr << std::endl;

		std::string rsa_pub_key(ptr);
		std::string token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6Ii1LSTNROW5OUjdiUm9meG1lWm9YcWJIWkdldyJ9.eyJhdWQiOiIxYzlmN2UxMy0yOTRjLTQ1NzItYjcxNC1iMjk1MTA3ZmIzMjYiLCJpc3MiOiJodHRwczovL2xvZ2luLm1pY3Jvc29mdG9ubGluZS5jb20vZWJiNTI1Y2YtMzBjZi00MThkLWE2ZjEtZThhNjc0NDFiOTcwL3YyLjAiLCJpYXQiOjE2NzY5NjI0MjAsIm5iZiI6MTY3Njk2MjQyMCwiZXhwIjoxNjc2OTY2MzIwLCJhY2N0IjowLCJhaW8iOiJBWlFBYS84VEFBQUFqUm1STlNuQ1Yrd3p6akYySzdLekZVaGVqenVWMUJzeW5QeHA4WmV2MUsrSndYZ2FXUEhXU1lqZzJxWlFoUDV2UnpKZ1R1dzNiVnhqT05pT0NkU1hEWlJHNWRVbHllM3E3NXdrcVdsWmUxZ3JxSXU4WWdIczFhQXN3NUEzZThmZkMxdEpBeXBTT3hkRndJbVVwaGx2NnlWcS94ZnRXRVJVMmdwd0Yxb1JYTFEzenNPejFCWFg5VHIrS1dBUUVVZ2wiLCJhdXRoX3RpbWUiOjE2NzY1MjIyNzYsImN0cnkiOiJWTiIsImVtYWlsIjoidGVzdG1hc3NtYWlsMTRAZ21haWwuY29tIiwiZmFtaWx5X25hbWUiOiJ0byIsImdpdmVuX25hbWUiOiJraGFpIiwiaWRwIjoiaHR0cHM6Ly9zdHMud2luZG93cy5uZXQvOTE4ODA0MGQtNmM2Ny00YzViLWIxMTItMzZhMzA0YjY2ZGFkLyIsImlwYWRkciI6IjExOS44Mi4xMzkuMTAyIiwibG9naW5faGludCI6Ik8uQ2lRd01EQXdNREF3TUMwd01EQXdMVEF3TURBdE1EUmhZUzB5TnpJelpUUmtOakZqWlRJU0pEa3hPRGd3TkRCa0xUWmpOamN0TkdNMVlpMWlNVEV5TFRNMllUTXdOR0kyTm1SaFpCb1lkR1Z6ZEcxaGMzTnRZV2xzTVRSQVoyMWhhV3d1WTI5dElHdz0iLCJuYW1lIjoia2hhaSB0byIsIm5vbmNlIjoiezliYmNmMDc4LWM3YzUtNGIyNy1hMDk0LTE2MmI1NjMxMTQzYn0iLCJvaWQiOiIzOTNkZTA2Ni1kZTk5LTRhYmItYjZhNS01MjVlOGQ1OGM2NGIiLCJwcmVmZXJyZWRfdXNlcm5hbWUiOiJ0ZXN0bWFzc21haWwxNEBnbWFpbC5jb20iLCJwcm92X2RhdGEiOlt7ImF0Ijp0cnVlLCJwcm92IjoiZ2l0aHViLmNvbSIsImFsdHNlY2lkIjoiMTAzMTE0Mzc1In1dLCJyaCI6IjAuQVVvQXp5VzE2ODh3alVHbThlaW1kRUc1Y0JOLW54eE1LWEpGdHhTeWxSQl9zeWFKQUhJLiIsInNpZCI6ImQ0ZGQ0ZDZjLWVjYjMtNGM1ZC04ZTM2LTI0MTY3NTc1OGNkMiIsInN1YiI6ImR2c19lYjFhdUZURF9ZWllGT1JaMHlzamRhWlI0cmZLSFoxLWpxQVJIX2siLCJ0ZW5hbnRfY3RyeSI6IlZOIiwidGVuYW50X3JlZ2lvbl9zY29wZSI6IkFTIiwidGlkIjoiZWJiNTI1Y2YtMzBjZi00MThkLWE2ZjEtZThhNjc0NDFiOTcwIiwidXRpIjoiUXAxcEJ5Umdfa3VmZGY3RUx5TnpBQSIsInZlciI6IjIuMCIsInhtc19wbCI6ImVuIiwieG1zX3RwbCI6ImVuIn0.GsD-1v3F2_9tIXiaerUN4XLlKJGyFQf3JReKlygTEDqniyZTynvvixxja6biKLG-tiPWSseE1HdjHYPtmG7FwWRNBkMh4TujSdzJMfS0uY61NuR-qEEiIJTxpQgUtOQ170mantEu6OVeT77aV7OfjCjbDmfGC8JA2MBaGrQgp7ZePfRbqT17hG8XI0p3Nf1jHIWGShLvZRFoedEmcktkZjRIOLv8gk4cbix-_SJLe2h_hMQ5WUNm02Xlr4xk_PwsCP7XT2xsMugDMkvndvEwKd4DJrsIzFeSd2iullsztQQtfGDOLQ3pfuhGX55GTnmMR-kzQ-ZeR_cVTzaWX4L_-Q";

		jwt::algorithm::rsa rsa = jwt::algorithm::rs256(rsa_pub_key);

		auto verify = jwt::verify().allow_algorithm(rsa);

		auto decoded = jwt::decode(token);

		try {
			verify.verify(decoded);
		}
		catch (std::exception& e) {
			std::cout << "Invalid token. " << e.what() << std::endl;
			return 0;
		}

		std::cout << "Signature verified" << std::endl;
	}

	return 0;*/

	OpenSSL_add_all_algorithms();

	
	/*ERR_load_crypto_strings();

	// Get subject name from PEM
	FILE* pem = fopen(R"(C:\Users\kto\OneDrive - OPSWAT\Desktop\LMS-13888 samples\xlsx.pem)", "rb");

	// obtain file size
	fseek(pem, 0, SEEK_END);
	long lenData = ftell(pem);
	rewind(pem);

	char* pData = new char[lenData];
	fread((void*)pData, 1, lenData, pem);
	fclose(pem);

	// https://stackoverflow.com/questions/6509189/extract-pem-certificate-information-programmatically-using-openssl
	BIO* bio_mem = BIO_new(BIO_s_mem());
	BIO_puts(bio_mem, (const char*)pData);
	X509* x509 = PEM_read_bio_X509(bio_mem, NULL, NULL, NULL);
	if (x509 == NULL)
	{
		//Error in d2i_X509_bio
		unsigned int errCode = ERR_get_error();

		printf("\nError: %s\n", ERR_error_string(errCode, NULL));
		printf("\nLib: %s\n", ERR_lib_error_string(errCode));
		printf("\nFunc: %s\n", ERR_func_error_string(errCode));
		printf("\nReason: %s\n", ERR_reason_error_string(errCode));
		return 0;
	}
	else
	{
		X509_NAME *subject_name = X509_get_subject_name(x509);
		//char* cn = new char[256];
		//memset(cn, 0, 256);
		char cn[256] = {};
		X509_NAME_get_text_by_NID(subject_name, NID_commonName, cn, 256);
		printf("Subject CN: %s\n", cn);
	}
	BIO_free_all(bio_mem);
	X509_free(x509);*/

	/*------------------------ READ SUBJECT FIELD OF DIGITAL SIGNATURE FOR PE FILES ------------------------*/
	try {
		//CertificateParser parser(argv[1]);
		CertificateParser parser(R"(C:\Users\kto\OneDrive - OPSWAT\Desktop\LMS-13888 samples\AdobeAIRInstaller.exe)");
		unsigned char* cert_data = nullptr;
		unsigned long cert_lengh = parser.GetCertificate(&cert_data);

		/*FILE* cert_file_1 = fopen(R"(C:\Users\kto\OneDrive - OPSWAT\Desktop\test.der)", "wb");
		fwrite(cert_data, 1, cert_lengh, cert_file_1);
		fclose(cert_file_1);*/


		BIO* bio = nullptr;
		X509* x509_cert = nullptr;
		X509_STORE* store = nullptr;
		X509_STORE_CTX* ctx = nullptr;

		FILE* cert_pem_file = fopen(R"(C:\Users\kto\OneDrive - OPSWAT\Desktop\LMS-13888 samples\stackexchange.pem)", "rb");
		fseek(cert_pem_file, 0, SEEK_END);
		long lenData = ftell(cert_pem_file);
		fseek(cert_pem_file, 0, SEEK_SET);

		char* pData = new char[lenData];
		memset(pData, 0, lenData);
		fread((void*)pData, 1, lenData, cert_pem_file);
		fclose(cert_pem_file);

		bio = BIO_new_mem_buf((void*)(pData), lenData);
		x509_cert = PEM_read_bio_X509(bio, nullptr, nullptr, nullptr);
		store = X509_STORE_new();
		if (1 != X509_STORE_add_cert(store, x509_cert)) {
			std::cout << "Failed to validate cert 1";
			return 1;
		}

		ctx = X509_STORE_CTX_new();
		if (1 != X509_STORE_CTX_init(ctx, store, x509_cert, NULL)) {
			unsigned long err = ERR_get_error();
			std::cout << "Failed to validate cert 2. " << ERR_GET_REASON(err) << std::endl;
			return 1;
		}
		if (1 != X509_verify_cert(ctx)) {
			unsigned long err = ERR_get_error();
			char buf_err[1024] = { 0 };
			ERR_error_string(err, buf_err);
			//std::cout << "Failed to validate cert 3. " << buf_err << std::endl;
			//return 1;
		}


		/*FILE* cert_file = fopen(R"(C:\Users\kto\OneDrive - OPSWAT\Desktop\two_signer.der)", "wb");
		fwrite(cert_data, 1, cert_lengh, cert_file);
		fclose(cert_file);*/

		//https://stackoverflow.com/questions/58065209/get-details-from-pkcs7-cms-via-c
		PKCS7* p7 = d2i_PKCS7(NULL, (const unsigned char **)&cert_data, cert_lengh);

		if (p7 == NULL) {
			//unsigned int errCode = ERR_get_error();

			//printf("\nError: %s\n", ERR_error_string(errCode, NULL));
			//printf("\nLib: %s\n", ERR_lib_error_string(errCode));
			//printf("\nFunc: %s\n", ERR_func_error_string(errCode));
			//printf("\nReason: %s\n", ERR_reason_error_string(errCode));
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

		/*for (int i = 0; certs && i < sk_X509_num(certs); i++) {
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
			printf("Subject CN: %s\n", cn);
			delete[]cn;
		}*/

		stack_st_X509* signers_stack_ptr = PKCS7_get0_signers(p7, nullptr, 0);
		auto signers_stack = STACK_OF_X509_ptr(signers_stack_ptr, SK_X509_free);

		for (auto i = 0; i < sk_X509_num(signers_stack.get()); ++i) {
			X509* cert = sk_X509_value(signers_stack.get(), i);
			/*auto subject = OpenSSL_ptr(X509_NAME_oneline(X509_get_subject_name(cert), nullptr, 0), OpenSSL_free);
			auto issuer = OpenSSL_ptr(X509_NAME_oneline(X509_get_issuer_name(cert), nullptr, 0), OpenSSL_free);

			std::cout << "Subject: " << std::string(subject.get()) << std::endl;
			std::cout << "Issuer: " << std::string(issuer.get()) << std::endl;*/

			/*char* cn = new char[256];
			memset(cn, 0, 256);*/
			char cn[256] = {};
			X509_NAME_get_text_by_NID(X509_get_subject_name(cert), NID_commonName, cn, 256);
			//printf("Subject CN: %s\n", cn);

			// calculate & print fingerprint
			unsigned char md[EVP_MAX_MD_SIZE];
			unsigned int n;
			const EVP_MD* digest = EVP_get_digestbyname("sha1");
			X509_digest(cert, digest, md, &n);
			printf("\nFingerprint: ");
			for (int pos = 0; pos < 19; pos++)
				printf("%02x:", md[pos]);
			printf("%02x\n", md[19]);

			print_cert(cert, i);
		}

		/*std::cout << "Content Type: ";
		const unsigned char *SpcIndirectDataOid = OBJ_get0_data(p7->d.sign->contents->type);
		for (int i = 0; i < OBJ_length(p7->d.sign->contents->type); i++)
			printf("%02x ", SpcIndirectDataOid[i]);
		std::cout << std::endl;
		{
			char text[128] = { 0 };
			OBJ_obj2txt(text, sizeof(text), p7->d.sign->contents->type, 1);
			std::cout << text << endl;
		}*/	

		getDetails(p7);
		
		STACK_OF(PKCS7_SIGNER_INFO)* signer_info = PKCS7_get_signer_info(p7);

		for (int i = 0; i < sk_PKCS7_SIGNER_INFO_num(signer_info); i++) {

			std::cout << i << std::endl;

			PKCS7_SIGNER_INFO* si = sk_PKCS7_SIGNER_INFO_value(signer_info, i);

			int md_nid = OBJ_obj2nid(si->digest_alg->algorithm);
			printf("Digest Algorithm: %s\n", (md_nid == NID_undef) ? "UNKNOWN" : OBJ_nid2ln(md_nid));

			int md_enc_nid = OBJ_obj2nid(si->digest_enc_alg->algorithm);
			printf("Digest Encryption Algorithm: %s\n", (md_enc_nid == NID_undef) ? "UNKNOWN" : OBJ_nid2ln(md_enc_nid));

			STACK_OF(X509_ATTRIBUTE)* auth_attr = PKCS7_get_signed_attributes(si);

			ASN1_OBJECT* object;
			X509_ATTRIBUTE* attr;
			ASN1_STRING* value = NULL;
			char object_txt[128];
			const unsigned char* data;
			for (int i = 0; i < X509at_get_attr_count(auth_attr); i++) {
				X509_ATTRIBUTE* attr = X509at_get_attr(auth_attr, i);
				ASN1_OBJECT* object = X509_ATTRIBUTE_get0_object(attr);
				if (object == NULL)
					continue;
				object_txt[0] = 0x00;
				OBJ_obj2txt(object_txt, sizeof object_txt, object, 1);
				printf("[auth_attr] %s\n", object_txt);
				if (!strcmp(object_txt, PKCS9_MESSAGE_DIGEST)) {
					/* PKCS#9 message digest - Policy OID: 1.2.840.113549.1.9.4 */
					ASN1_STRING* digest = static_cast<ASN1_STRING*>(X509_ATTRIBUTE_get0_data(attr, 0, V_ASN1_OCTET_STRING, NULL));
					data = ASN1_STRING_get0_data(digest);
					int len = ASN1_STRING_length(digest);
					print_hash("Message digest", "", const_cast<unsigned char*>(data), len);
				}
				else if (!strcmp(object_txt, PKCS9_SIGNING_TIME)) {
					/* PKCS#9 signing time - Policy OID: 1.2.840.113549.1.9.5 */
					ASN1_UTCTIME* time = static_cast<ASN1_UTCTIME*>(X509_ATTRIBUTE_get0_data(attr, 0, V_ASN1_UTCTIME, NULL));
					time_t signtime = asn1_get_time_t(time);

					printf("Signed time\n");
					print_time_t(signtime);
				} else if (!strcmp(object_txt, SPC_SP_OPUS_INFO_OBJID)) {
					/* Microsoft OID: 1.3.6.1.4.1.311.2.1.12 */
					value = static_cast<ASN1_STRING*>(X509_ATTRIBUTE_get0_data(attr, 0, V_ASN1_SEQUENCE, NULL));
					if (value == NULL)
						continue;
					data = ASN1_STRING_get0_data(value);
					int len = ASN1_STRING_length(value);
					for (int i = 0; i < len; i++)
						printf("%02x",data[i]);
						
					std::cout << std::endl;
				}
				else if (!strcmp(object_txt, SPC_STATEMENT_TYPE_OBJID)) {
					/* Microsoft OID: 1.3.6.1.4.1.311.2.1.11 */
					value = static_cast<ASN1_STRING*>(X509_ATTRIBUTE_get0_data(attr, 0, V_ASN1_SEQUENCE, NULL));
					if (value == NULL)
						continue;
					data = ASN1_STRING_get0_data(value);
					int len = ASN1_STRING_length(value);
					std::cout << "SPC_STATEMENT_TYPE_OBJID" << std::endl;
					for (int i = 0; i < len; i++)
						printf("%02x", data[i]);

					std::cout << std::endl;
				} else if (!strcmp(object_txt, CONTENT_TYPE_OBJID)) {
					ASN1_TYPE* av = X509_ATTRIBUTE_get0_type(attr, 0);
					if (NULL != av)
					{
						std::cout << "Content Type: ";
						const unsigned char *content_type;
						content_type = OBJ_get0_data(av->value.object);
						for (int i = 0; i < OBJ_length(av->value.object); i++)
							printf("%02x ", content_type[i]);
						std::cout << std::endl;
					}
				}
			}

			STACK_OF(X509_ATTRIBUTE)* unauth_attr = PKCS7_get_attributes(si);
			for (int i = 0; i < X509at_get_attr_count(unauth_attr); i++) {
				attr = X509at_get_attr(unauth_attr, i);
				object = X509_ATTRIBUTE_get0_object(attr);
				if (object == NULL)
					continue;
				object_txt[0] = 0x00;
				OBJ_obj2txt(object_txt, sizeof object_txt, object, 1);
				printf("[unauth_attr] %s\n", object_txt);
				if (0 == strcmp(object_txt, SPC_NESTED_SIGNATURE_OBJID)) {
					/* OID: 1.3.6.1.4.1.311.2.4.1 */
					PKCS7* nested;
					std::cout << "\nNumber of nested signatures: " << X509_ATTRIBUTE_count(attr) << std::endl;
					for (int j = 0; j < X509_ATTRIBUTE_count(attr); j++) {
						value = static_cast<ASN1_STRING*>(X509_ATTRIBUTE_get0_data(attr, j, V_ASN1_SEQUENCE, NULL));
						if (value == NULL) {
							continue;
						}
						data = ASN1_STRING_get0_data(value);
						nested = d2i_PKCS7(NULL, &data, ASN1_STRING_length(value));
						if (nested) {

							X509* cert;
							int i, count;

							count = sk_X509_num(nested->d.sign->cert);
							printf("\nNumber of certificates: %d\n", count);
							for (i = 0; i < count; i++) {
								cert = sk_X509_value(nested->d.sign->cert, i);
								if ((cert == NULL) || (!print_cert(cert, i)))
									return 0; /* FAILED */
							}
							PKCS7_free(nested);
						}
					}
				}
				else if (!strcmp(object_txt, PKCS9_COUNTER_SIGNATURE)) {
					/* Authenticode Timestamp - Policy OID: 1.2.840.113549.1.9.6 */
					PKCS7_SIGNER_INFO* countersi;
					time_t time;
					value = static_cast<ASN1_STRING*>(X509_ATTRIBUTE_get0_data(attr, 0, V_ASN1_SEQUENCE, NULL));
					if (value == NULL)
						continue;
					data = ASN1_STRING_get0_data(value);
					countersi = d2i_PKCS7_SIGNER_INFO(NULL, &data, ASN1_STRING_length(value));
					if (countersi == NULL) {
						printf("Error: Authenticode Timestamp could not be decoded correctly\n");
						ERR_print_errors_fp(stdout);
						continue;
					}
					time = si_get_time(countersi);
					if (time != INVALID_TIME) {
						printf("\The signature is timestamped: ");
						print_time_t(time);
					}
					else {
						printf("Error: PKCS9_TIMESTAMP_SIGNING_TIME attribute not found\n");
						PKCS7_SIGNER_INFO_free(countersi);
					}
				}
				else if (!strcmp(object_txt, SPC_RFC3161_OBJID)) {
					/* RFC3161 Timestamp - Policy OID: 1.3.6.1.4.1.311.3.3.1 */
					CMS_ContentInfo* cms = NULL;
					time_t time;
					value = static_cast<ASN1_STRING*>(X509_ATTRIBUTE_get0_data(attr, 0, V_ASN1_SEQUENCE, NULL));
					if (value == NULL)
						continue;
					data = ASN1_STRING_get0_data(value);

					int len = ASN1_STRING_length(value);
					cms_get_time_1(data, len);


					cms = d2i_CMS_ContentInfo(NULL, &data, ASN1_STRING_length(value));
					if (cms == NULL) {
						printf("Error: RFC3161 cms could not be decoded correctly\n");
						ERR_print_errors_fp(stdout);
						continue;
					}

					time = cms_get_time(cms);
					if (time != INVALID_TIME) {
						printf("\nThe signature is timestamped: ");
						print_time_t(time);
					}
					else {
						printf("Error: Corrupt RFC3161 Timestamp embedded content\n");
						CMS_ContentInfo_free(cms);
						ERR_print_errors_fp(stdout);
					}
				}
			}
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