#pragma once

#include <Windows.h>
#include <wincrypt.h>
#include <string>

static const char* ENCRYPTION_KEY = "6d6e976t2wrvg7xz";
static const int ENCRYPTION_KEY_LEN = 16;
static const int PASSWORD_BUFFER_LEN = 64;
static const int CONTENT_BUFFER_LEN = 200;

class CryptWrapper
{
private:
	HCRYPTPROV hCryptProv;
	HCRYPTHASH hHash;
	HCRYPTKEY hKey{ 0 };
public:
	CryptWrapper();
	void Encrypt(const char* passwordArg, const char* filenameArg, const char* contentArg);
	void Decrypt(const char* passwordArg, const char* filenameArg);
	~CryptWrapper();
};