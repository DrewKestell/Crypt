#pragma once

#include <Windows.h>
#include <wincrypt.h>
#include <string>

class CryptWrapper
{
private:
	HCRYPTPROV hCryptProv;
	HCRYPTHASH hHash;
	HCRYPTKEY hKey{ 0 };
public:
	CryptWrapper();
	void Encrypt(const char* passwordArg, const char* filenameArg, const char* contentArg);
	std::string Decrypt(const char* passwordArg, const char* filenameArg, bool& success);
	~CryptWrapper();
};