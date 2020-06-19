#include <stdio.h>

int main(int argc, char* argv[])
{
    printf("%i", argc);

    for (auto i = 0; i < argc; i++)
    {
        printf(argv[i]);
    }
}
