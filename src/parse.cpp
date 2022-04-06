#include "parse.h"

CertificateParser::CertificateParser()
{
	f = NULL;
}

CertificateParser::CertificateParser(const std::string& in_pe_file)
{
	f = fopen(in_pe_file.c_str(), "rb");
	if (f == NULL) {
		throw "Failed to open file!!!";
	}
}

CertificateParser::~CertificateParser() {
	if (f != NULL) {
		fclose(f);
	}
}

unsigned long CertificateParser::GetCertificate(unsigned char **out_cert_data)
{
	// Jump to offset 0x3c. Value specified at offset 0x3c is a 4-byte offset that points to  IMAGE_NT_HEADER
	fseek(f, 0x3c, SEEK_SET);

	//printf("current offset: %x\n", ftell(f));

	unsigned long offset_image_nt_header = 0;
	fread(&offset_image_nt_header, 1, 4, f);

	//printf("image_nt_header: %x\n", offset_image_nt_header);

	// Check if this is PE file by reading first 4-byte in IMAGE_NT_HEADER
	// https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_nt_headers64
	fseek(f, offset_image_nt_header, SEEK_SET);
	unsigned long file_signature = 0;
	fread(&file_signature, 1, 4, f);

	//printf("file_signature: %x\n", file_signature);

	if (file_signature != 0x4550) {
		throw "Not PE file format!!!";
	}

	// Check PE file is 32-bit or 64-bit by reading first 2-byte in IMAGE_FILE_HEADER 
	// https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_file_header
	unsigned short machine_type = 0;
	fread(&machine_type, 1, 2, f);

	//printf("machine_type: %x\n", machine_type);
	bool is_32bit = (machine_type == 0x014c);

	// Jump 18 bytes to go to IMAGE_OPTIONAL_HEADER
	fseek(f, 18, SEEK_CUR);
	//printf("image_optional_header: %x\n", ftell(f));

	// At IMAGE_OPTIONAL_HEADER, jump to next 128/144 bytes (if file is 32/64 bit) to read offset of Certificate Table
	// https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_data_directory
	if (is_32bit) {
		fseek(f, 128, SEEK_CUR);
	} else {
		fseek(f, 144, SEEK_CUR);
	}
	unsigned long cert_table_offset = 0;
	fread(&cert_table_offset, 1, 4, f);
	//printf("certificate_table_offset: %x\n", cert_table_offset);

	// Jump to Certificate Table
	fseek(f, cert_table_offset, SEEK_SET);

	//printf("current offset: %x\n", ftell(f));
	
	// Read lengh of certificate data from Certificate table
	// https://docs.microsoft.com/en-us/windows/win32/debug/pe-format#the-attribute-certificate-table-image-only
	unsigned long cert_lengh = 0;
	fread(&cert_lengh, 1, 4, f);
	
	// Jump over 4 bytes to access certificate data
	fseek(f, 4, SEEK_CUR);

	// Create buffer to contain certificate data and read data
	cert_lengh = cert_lengh - 8; // do not count size of dwLength, wRevision and wCertificateType
	*out_cert_data = new unsigned char[cert_lengh];

	//printf("current_offset: %x\n", ftell(f));
	//printf("cert_lengh: %x\n", cert_lengh);

	fread(*out_cert_data, 1, cert_lengh, f);

	//printf("Done!!!\n");

	return cert_lengh;
}


