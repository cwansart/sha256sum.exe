#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>

int main(int argc, char *argv[])
{
    // args
    if (argc < 2)
    {
        printf("missing file parameter\n");
        return 1;
    }

    // open file
    FILE *file = NULL;
    errno_t err = fopen_s(&file, argv[1], "rb");

    if (err != 0)
    {
        printf("failed to open the file, err code: %d\n", err);
        return 1;
    }

    // hash
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!EVP_DigestInit_ex(ctx, EVP_sha256(), NULL))
    {
        printf("failed to init digest.\n");
        EVP_MD_CTX_free(ctx);
        fclose(file);
        return 1;
    }

    char buf[1024];
    size_t nread;
    while ((nread = fread(buf, 1, sizeof buf, file)) > 0)
    {
        if (!EVP_DigestUpdate(ctx, buf, nread))
        {
            printf("failed to update digest\n");
            EVP_MD_CTX_free(ctx);
            fclose(file);
            return 1;
        }
    }

    if (!EVP_DigestFinal_ex(ctx, hash, &hash_len))
    {
        printf("failed to finalize digest\n");
        EVP_MD_CTX_free(ctx);
        fclose(file);
        return 1;
    }

    EVP_MD_CTX_free(ctx);

    // print hash
    for (unsigned int i = 0; i < hash_len; i++)
    {
        printf("%02x", hash[i]);
    }

    fclose(file);
    return 0;
}
