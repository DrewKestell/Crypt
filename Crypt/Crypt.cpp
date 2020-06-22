#include <Windows.h>
#include <wincrypt.h>
#include <stdio.h>
#include "CryptWrapper.h"

int main(int argc, char* argv[])
{
    printf("Crypt.exe v1.0\n");

    if (argc == 1 || (strcmp(argv[1], "e") && strcmp(argv[1], "d")) || (!strcmp(argv[1], "e") && argc != 5) || (!strcmp(argv[1], "d") && argc != 4))
    {
        printf("ERROR: Incorrect usage. Use e to encrypt, or d to decrypt.\n");
        printf("Crypt e <password> <filename> <content>\n");
        printf("Crypt d <password> <filename>\n");
        return 1;
    }

    CryptWrapper cryptWrapper;

    const char* commandArg = argv[1];
    const char* passwordArg = argv[2];
    const char* filenameArg = argv[3];

    if (!strcmp(commandArg, "e"))
    {
        printf("Starting encryption...\n");

        const auto passwordLength = strlen(passwordArg);
        if (passwordLength < 4 || passwordLength > 32)
        {
            printf("ERROR: Password must be between 4 and 32 characters in length.\n");
            return 1;
        }

        const char* contentArg = argv[4];
        const auto contentLength = strlen(contentArg);
        if (contentLength < 1 || contentLength > 100)
        {
            printf("ERROR: Content must be between 1 and 100 characters in length.\n");
            return 1;
        }

        cryptWrapper.Encrypt(passwordArg, filenameArg, contentArg);

        printf("Encryption complete!\n");
    }
    else if (!strcmp(commandArg, "d"))
    {
        printf("Starting decryption...\n");

        bool success;
        auto content = cryptWrapper.Decrypt(passwordArg, filenameArg, success);

        if (success)
            printf("Decryption successful! Archive contains the following content:\n");

        printf("%s\n", content.c_str());
    }
}
