#pragma once
#include <stdexcept>
#undef AFX_DATA
#define AFX_DATA AFX_EXT_DATA
// <body of your header file>
#include <curl/curl.h>
#include <string>
#include<iostream>
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
#include <pthread.h>
#define u32 uint32_t
#define u16 uint16_t
#define u8 uint8_t
#define u64 uint64_t
#include <sys/stat.h>
#include <fcntl.h>
#undef AFX_DATA
#define AFX_DATA

using namespace std;

struct NPpp_FRAMEWORK {
	char magic[4];
	uint32_t version;
	uint16_t size;
	uint8_t unk[6];
	uint8_t random[0x10];
	uint8_t eid0_dec[0x60];
	uint64_t unix_timestamp;
	char npid[0x10];
	uint8_t pad[0x148];
	uint8_t hmac_sha256[0x20];
};

namespace DllPsnFunk
{
	
	extern "C" { __declspec(dllexport) void fn_generate_unique_framework(NPpp_FRAMEWORK* FRAMEWORK); }
	extern "C" { __declspec(dllexport) char* fn_generate_hwframework(char* idps_ascii, uint8_t* npid_ascii); }
	extern "C" { __declspec(dllexport) char*  fn_base64decode(uint8_t* b64_decode_this, int decode_this_many_bytes); }
	extern "C" { __declspec(dllexport) CURLcode fn_curl_global_init(long flags); }
	extern "C" { __declspec(dllexport) CURL* fn_curl_easy_init(); }
	extern "C" { __declspec(dllexport) int fn_choose_rand_idps(uint8_t* idps, uint8_t* ps3_ids); }
	extern "C" { __declspec(dllexport) struct curl_slist* fn_curl_slist_append(struct curl_slist*, const char*); }

	extern "C" { __declspec(dllexport) CURLcode fn_curl_easy_setopt(CURL* curl, CURLoption option, void* d);	}
	
	
	

	extern "C" { __declspec(dllexport) CURLcode fn_sslctxfun(CURL* curl, void* sslctx, void* parm); }


	extern "C" { __declspec(dllexport) char* psnfunkmain(char* email, char* pass, char* consoleid, char* proxy, int proxytype); }
	extern "C" { __declspec(dllexport) char* regMethodConfig(char* email, char* pass, char* consoleid, char* proxy, int proxytype); }
	extern "C" { __declspec(dllexport) char* regMethodConfig2(char* email, char* pass, char* consoleid, char* proxy, int proxytype); }
	extern "C" { __declspec(dllexport) char* crssConfigMethod(char* email, char* pass, char* consoleid, char* proxy, int proxytype); }
	extern "C" { __declspec(dllexport) char* kdpConfigMethod(char* email, char* pass, char* consoleid, char* proxy, int proxytype); }
	extern "C" { __declspec(dllexport) char* capConfigMethod(char* email, char* pass, char* consoleid, char* proxy, int proxytype); }
	extern "C" { __declspec(dllexport) char* cdpConfigMethod(char* email, char* pass, char* consoleid, char* proxy, int proxytype); }
	extern "C" { __declspec(dllexport) char* authConfigMethod(char* email, char* pass, char* consoleid, char* proxy, int proxytype); }
	extern "C" { __declspec(dllexport) char* crssVitaConfigMethod(char* email, char* pass, char* consoleid, char* proxy, int proxytype); }
	extern "C" { __declspec(dllexport) char* bindConfigMethod(char* email, char* pass, char* consoleid, char* proxy, int proxytype); }
	extern "C" { __declspec(dllexport) char* getToken(char* navResponse, char* proxy, int proxytype); }


}