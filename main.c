#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>

int main(int argc, char *argv[])
{
    if (argc < 2)
    {
        printf("missing file parameter");
        return 1;
    }

    FILE *file = NULL;
    errno_t err = fopen_s(&file, argv[1], "rb");

    if (err != 0)
    {
        printf("Failed to open the file. Error code: %d\n", err);
        return 1;
    }

    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len;

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);

    char buf[1024];
    size_t nread;
    while ((nread = fread(buf, 1, sizeof buf, file)) > 0)
    {
        EVP_DigestUpdate(ctx, buf, nread);
    }

    EVP_DigestFinal_ex(ctx, hash, &hash_len);
    EVP_MD_CTX_free(ctx);

    unsigned int i;
    for (i = 0; i < hash_len; i++)
    {
        printf("%02x", hash[i]);
    }

    fclose(file);
    return 0;
}
