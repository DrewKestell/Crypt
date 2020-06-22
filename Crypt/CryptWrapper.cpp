#include "CryptWrapper.h"

CryptWrapper::CryptWrapper()
{
	CryptAcquireContext(&hCryptProv, 0, 0, PROV_RSA_FULL, 0);
	CryptCreateHash(hCryptProv, CALG_MD5, 0, 0, &hHash);
}

void CryptWrapper::Encrypt(const char* passwordArg, const char* filenameArg, const char* contentArg)
{
	CryptHashData(hHash, (BYTE*)passwordArg, strlen(passwordArg), CRYPT_USERDATA);
	CryptDeriveKey(hCryptProv, CALG_RC2, hHash, CRYPT_NO_SALT, &hKey);

	// first call CryptEncrypt without providing content.
	// this will return the required buffer size for the encrypted content in dwHashLen.
	DWORD dwHashLen = strlen(contentArg);
	CryptEncrypt(hKey, 0, true, 0, 0, &dwHashLen, 0);

	// next create a buffer with the size retrieved above
	BYTE* buffer = new BYTE[dwHashLen];
	ZeroMemory(buffer, dwHashLen);
	memcpy(buffer, contentArg, strlen(contentArg));

	// finally call CryptEncrypt to actually encrypt the content
	DWORD dataLength = strlen(contentArg);
	CryptEncrypt(hKey, 0, true, 0, buffer, &dataLength, dwHashLen);

	CryptDestroyKey(hKey);

	// now save the password and encrypted content in the file.
	// our implementation is simple, and it will overwrite the
	//   file if it already exists.
	// we should also NOT be storing the unencrypted password
	//   here, but the purpose of the exercise is to show how
	//   this flaw can be discovered and abused through
	//   reverse engineering.
	auto hFile = CreateFileA(
		filenameArg,
		GENERIC_READ | GENERIC_WRITE,
		0,
		0,
		CREATE_ALWAYS,
		FILE_ATTRIBUTE_NORMAL,
		0);

	// write password to file
	BYTE pwBuffer[32];
	ZeroMemory(pwBuffer, 32);
	memcpy(pwBuffer, passwordArg, strlen(passwordArg));
	DWORD bytesWritten;
	WriteFile(hFile, pwBuffer, 32, &bytesWritten, 0);

	SetFilePointer(hFile, 32, 0, 0);

	// write encrypted content to file
	WriteFile(hFile, buffer, dwHashLen, &bytesWritten, 0);
}

std::string CryptWrapper::Decrypt(const char* passwordArg, const char* filenameArg, bool& success)
{
	OFSTRUCT of = { 0 };
	of.cBytes = sizeof(of);

	// first check to see if the file exists. if not, return an empty string;
	const auto hFile = OpenFile(filenameArg, &of, OF_EXIST);

	if (hFile == -1)
	{
		success = false;
		return "ERROR: File not found.";
	}

	// if it exists, open it for reading
	const auto fileHandle = CreateFileA(
		filenameArg,
		GENERIC_READ,
		FILE_SHARE_READ,
		0,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		0);

	// first, read the first 32 bytes from the archive to retrieve the password
	DWORD bytesRead;
	BYTE passwordBuffer[32];
	ZeroMemory(passwordBuffer, 32);
	ReadFile(fileHandle, passwordBuffer, 32, &bytesRead, 0);

	const char* password = reinterpret_cast<const char*>(passwordBuffer);
	if (strcmp(password, passwordArg))
	{
		success = false;
		return "ERROR: Invalid password.";
	}

	SetFilePointer(fileHandle, 32, 0, 0);

	// if the password is correct, read the encrypted bytes from the file
	BYTE contentBuffer[200];
	ZeroMemory(contentBuffer, 200);
	ReadFile(fileHandle, contentBuffer, 200, &bytesRead, 0);

	// then decrypt the data
	CryptHashData(hHash, (BYTE*)passwordArg, strlen(passwordArg), CRYPT_USERDATA);
	CryptDeriveKey(hCryptProv, CALG_RC2, hHash, CRYPT_NO_SALT, &hKey);
	DWORD contentBufferLen{ strlen(reinterpret_cast<const char*>(contentBuffer)) };
	CryptDecrypt(hKey, hHash, true, 0, contentBuffer, &contentBufferLen);

	auto content = reinterpret_cast<const char*>(contentBuffer);
	success = true;
	return std::string(content, contentBufferLen);
}

CryptWrapper::~CryptWrapper()
{
	CryptDestroyHash(hHash);
	CryptReleaseContext(hCryptProv, 0);
}