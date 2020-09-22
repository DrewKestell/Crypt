#include "CryptWrapper.h"

CryptWrapper::CryptWrapper()
{
	CryptAcquireContext(&hCryptProv, 0, 0, PROV_RSA_FULL, 0);
	CryptCreateHash(hCryptProv, CALG_MD5, 0, 0, &hHash);
}

void CryptWrapper::Encrypt(const char* passwordArg, const char* filenameArg, const char* contentArg)
{
	const auto passwordArgLen = strlen(passwordArg);
	const auto contentArgLen = strlen(contentArg);

	// create session key that we'll use for encryption
	CryptHashData(hHash, (BYTE*)ENCRYPTION_KEY, ENCRYPTION_KEY_LEN, CRYPT_USERDATA);
	CryptDeriveKey(hCryptProv, CALG_RC2, hHash, CRYPT_NO_SALT, &hKey);

	// determine size of encrypted password
	DWORD dwPasswordBufferLen = passwordArgLen;
	CryptEncrypt(hKey, 0, true, 0, 0, &dwPasswordBufferLen, 0);

	// encrypt the password and store in passwordBuffer
	BYTE* passwordBuffer = new BYTE[dwPasswordBufferLen];
	ZeroMemory(passwordBuffer, dwPasswordBufferLen);
	memcpy(passwordBuffer, passwordArg, passwordArgLen);
	DWORD passwordLength = passwordArgLen;
	CryptEncrypt(hKey, 0, true, 0, passwordBuffer, &passwordLength, dwPasswordBufferLen);

	// copy encrypted password into 64 byte buffer so we always write 64 bytes to the file (padded with 0s)
	BYTE* encryptedPasswordBuffer = new BYTE[PASSWORD_BUFFER_LEN];
	ZeroMemory(encryptedPasswordBuffer, PASSWORD_BUFFER_LEN);
	memcpy(encryptedPasswordBuffer, passwordBuffer, dwPasswordBufferLen);

	// create the file (naive implementation will recreate the file even if it already exists)
	auto hFile = CreateFileA(
		filenameArg,
		GENERIC_READ | GENERIC_WRITE,
		0,
		0,
		CREATE_ALWAYS,
		FILE_ATTRIBUTE_NORMAL,
		0);

	// write encrypted password to file
	DWORD bytesWritten = 0;
	WriteFile(hFile, encryptedPasswordBuffer, PASSWORD_BUFFER_LEN, &bytesWritten, 0);

	// move file pointer ahead to immediately after the encrypted password
	SetFilePointer(hFile, PASSWORD_BUFFER_LEN, 0, 0);

	// determine size of encrypted conctent
	DWORD dwContentBufferLen = contentArgLen;
	CryptEncrypt(hKey, 0, true, 0, 0, &dwContentBufferLen, 0);

	// encrypt the content and store in contentBuffer
	BYTE* contentBuffer = new BYTE[dwContentBufferLen];
	ZeroMemory(contentBuffer, dwContentBufferLen);
	memcpy(contentBuffer, contentArg, contentArgLen);
	DWORD dataLength = contentArgLen;
	CryptEncrypt(hKey, 0, true, 0, contentBuffer, &dataLength, dwContentBufferLen);

	// write encrypted content to file
	WriteFile(hFile, contentBuffer, dwContentBufferLen, &bytesWritten, 0);

	CryptDestroyKey(hKey);

	printf("Encryption complete!\n");
}

void CryptWrapper::Decrypt(const char* passwordArg, const char* filenameArg)
{
	OFSTRUCT of = { 0 };
	of.cBytes = sizeof(of);

	// first check to see if the file exists. if not, return an empty string;
	const auto hFile = OpenFile(filenameArg, &of, OF_EXIST);
	if (hFile == -1)
	{
		printf("ERROR: File not found.\n");
		return;
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

	// create session key that we'll use for decryption
	CryptHashData(hHash, (BYTE*)ENCRYPTION_KEY, ENCRYPTION_KEY_LEN, CRYPT_USERDATA);
	CryptDeriveKey(hCryptProv, CALG_RC2, hHash, CRYPT_NO_SALT, &hKey);

	// read the first 64 bytes from the archive to retrieve the password
	DWORD bytesRead = 0;
	BYTE passwordBuffer[PASSWORD_BUFFER_LEN];
	ZeroMemory(passwordBuffer, PASSWORD_BUFFER_LEN);
	ReadFile(fileHandle, passwordBuffer, PASSWORD_BUFFER_LEN, &bytesRead, 0);

	// decrypt the password
	DWORD passwordBufferLen = PASSWORD_BUFFER_LEN;
	CryptDecrypt(hKey, hHash, true, 0, passwordBuffer, &passwordBufferLen);

	// the decrypted password will be shorter than the encrypted password,
	// so truncate the string and compare with the provided passwordArg
	auto decryptedPassword = reinterpret_cast<char*>(passwordBuffer);
	decryptedPassword[strlen(passwordArg)] = 0;
	if (strcmp(decryptedPassword, passwordArg))
	{
		printf("ERROR: Invalid password.\n");
		return;
	}

	// move file pointer to immediately following the password
	SetFilePointer(fileHandle, PASSWORD_BUFFER_LEN, 0, 0);

	// read the encrypted content from the file
	BYTE contentBuffer[CONTENT_BUFFER_LEN];
	ZeroMemory(contentBuffer, CONTENT_BUFFER_LEN);
	ReadFile(fileHandle, contentBuffer, CONTENT_BUFFER_LEN, &bytesRead, 0);

	// then decrypt the data
	DWORD contentBufferLen = bytesRead;
	CryptDecrypt(hKey, hHash, true, 0, contentBuffer, &contentBufferLen);

	auto content = reinterpret_cast<char*>(contentBuffer);
	content[contentBufferLen] = 0;

	printf("Decryption successful! Archive contains the following content:\n");
	printf("%s\n", content);
}

CryptWrapper::~CryptWrapper()
{
	CryptDestroyHash(hHash);
	CryptReleaseContext(hCryptProv, 0);
}