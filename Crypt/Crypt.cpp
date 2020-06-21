#include <Windows.h>
#include <wincrypt.h>
#include <stdio.h>

int main(int argc, char* argv[])
{
    HCRYPTPROV hCryptProv;
    HCRYPTHASH hHash;
    HCRYPTKEY hKey;

    CryptAcquireContext(
        &hCryptProv,
        NULL,
        NULL,
        PROV_RSA_FULL,
        0);

    CryptCreateHash(
        hCryptProv,
        CALG_MD5,
        0,
        0,
        &hHash);

    CryptHashData(
        hHash,
        (BYTE*)argv[1],
        strlen(argv[1]),
        CRYPT_USERDATA
    );

    CryptDeriveKey(
        hCryptProv,
        CALG_RC2,
        hHash,
        CRYPT_NO_SALT,
        &hKey);

    DWORD dwHashLen = strlen(argv[3]);
    auto res = CryptEncrypt(
        hKey,
        NULL,
        true,
        0,
        NULL,
        &dwHashLen,
        NULL);

    BYTE* buffer = new BYTE[dwHashLen];
    ZeroMemory(buffer, dwHashLen);
    memcpy(buffer, argv[3], strlen(argv[3]));

    DWORD dataLength = strlen(argv[3]);
    CryptEncrypt(
        hKey,
        NULL,
        true,
        0,
        buffer,
        &dataLength,
        dwHashLen);

    CryptDestroyKey(hKey);
    CryptDestroyHash(hHash);
    CryptReleaseContext(hCryptProv, 0);

    HANDLE hFile;
    hFile = CreateFileA(
        argv[2],
        GENERIC_READ | GENERIC_WRITE,
        0,
        NULL,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    BYTE pwBuffer[32];
    ZeroMemory(pwBuffer, 32);
    memcpy(pwBuffer, argv[1], strlen(argv[1]));
    DWORD bytesWritten;
    WriteFile(
        hFile,
        pwBuffer,
        32,
        &bytesWritten,
        NULL
    );

    SetFilePointer(
        hFile,
        32,
        NULL,
        0
    );

    WriteFile(
        hFile,
        buffer,
        dwHashLen,
        &bytesWritten,
        NULL
    );
}
