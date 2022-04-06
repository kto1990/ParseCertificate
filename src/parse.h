#include <string>

class CertificateParser
{
private:
	FILE* f;
public:
	CertificateParser();
	CertificateParser(const std::string& in_pe_file);
	~CertificateParser();

	unsigned long GetCertificate(unsigned char **out_cert_data);
};