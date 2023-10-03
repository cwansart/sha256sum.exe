#pragma comment(lib, "bcrypt.lib")

#include "sha256sum.h"
#include <bcrypt.h>

#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#define STATUS_UNSUCCESSFUL ((NTSTATUS)0xC0000001L)

#define HASH_LENGTH 64
#define LINE_BUFFER_SIZE 1024

typedef struct file_hash_t
{
    LPWSTR file;
    LPWSTR hash;
    struct file_hash_t* next;
} FileHash;

void RemoveBinaryPrefix(LPWSTR str)
{
    if (str[0] == L'*')
    {
        // Shift all characters one position to the left
        for (int i = 0; str[i] != L'\0'; ++i)
        {
            str[i] = str[i + 1];
        }
    }
}

ErrorCode CalcHash(__in Args* args, __out LPWSTR* file_hash, __in LPWSTR file)
{
    ErrorCode status = SUCCESS;
    HANDLE hFile;
    DWORD dwBytesRead;
    BYTE buffer[LINE_BUFFER_SIZE] = { 0 };

    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_HASH_HANDLE hHash = NULL;
    NTSTATUS hashStatus = STATUS_UNSUCCESSFUL;
    DWORD cbData = 0,
        cbHash = 0,
        cbHashObject = 0;
    PBYTE pbHashObject = NULL;
    PBYTE pbHash = NULL;

    RemoveBinaryPrefix(file);

    // open file
    hFile = CreateFileW(file,                  // File name
                        GENERIC_READ,          // Open for reading
                        0,                     // No sharing
                        NULL,                  // Default security
                        OPEN_EXISTING,         // Existing file only
                        FILE_ATTRIBUTE_NORMAL, // Normal file
                        NULL);
    if (hFile == INVALID_HANDLE_VALUE)
    {
        if (!args->status)
        {
            wchar_t errorMsg[MAX_PATH + 50];
            wsprintfW(errorMsg, L"failed to open file '%ls' with error: %lu\r\n", file, GetLastError());
            WriteConsoleW(GetStdHandle(STD_OUTPUT_HANDLE), errorMsg, lstrlenW(errorMsg), NULL, NULL);
        }
        status = CALC_HASH_FAILED_TO_OPEN_FILE;
        goto Cleanup;
    }

    // open an algorithm handle
    if (!NT_SUCCESS(hashStatus = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL, 0)))
    {
        if (!args->status)
        {
            printf("open an algorithm handle failed: %ld\n", hashStatus);
        }
        status = CALC_HASH_FAILED_TO_OPEN_ALG_HANDLE;
        goto Cleanup;
    }

    // calculate the size of the buffer to hold the hash object
    if (!NT_SUCCESS(hashStatus = BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PBYTE)&cbHashObject, sizeof(DWORD), &cbData, 0)))
    {
        if (!args->status)
        {
            printf("hash buffer size allocation failed, err: %ld\n", hashStatus);
        }
        status = CALC_HASH_FAILED_TO_ALLOCATE_HASH_BUFFER_SIZE;
        goto Cleanup;
    }

    // allocate the hash object on the heap
    pbHashObject = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbHashObject);
    if (NULL == pbHashObject)
    {
        if (!args->status)
        {
            printf("memory allocation for hash object failed\n");
        }
        status = CALC_HASH_FAILED_TO_ALLOCATE_HASH_OBJECT;
        goto Cleanup;
    }

    // calculate the length of the hash
    if (!NT_SUCCESS(hashStatus = BCryptGetProperty(hAlg, BCRYPT_HASH_LENGTH, (PBYTE)&cbHash, sizeof(DWORD), &cbData, 0)))
    {
        if (!args->status)
        {
            printf("hash length calculation failed: %ld\n", hashStatus);
        }
        status = CALC_HASH_FAILED_TO_CALC_HASH_LENGTH;
        goto Cleanup;
    }

    // allocate the hash buffer on the heap
    pbHash = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbHash);
    if (NULL == pbHash)
    {
        if (!args->status)
        {
            printf("memory allocation for hash buffer failed\n");
        }
        status = CALC_HASH_FAILED_TO_ALLOCATE_HASH_BUFFER;
        goto Cleanup;
    }

    // create a hash
    if (!NT_SUCCESS(hashStatus = BCryptCreateHash(hAlg, &hHash, pbHashObject, cbHashObject, NULL, 0, 0)))
    {
        if (!args->status)
        {
            printf("hash creation failed: %ld\n", hashStatus);
        }
        status = CALC_HASH_FAILED_TO_CREATE_HASH;
        goto Cleanup;
    }

    while (TRUE)
    {
        if (!ReadFile(hFile, buffer, sizeof(buffer), &dwBytesRead, NULL))
        {
            if (!args->status)
            {
                printf("read file failed: %lu\n", GetLastError());
            }
            status = CALC_HASH_FAILED_TO_READ;
            goto Cleanup;
        }

        if (dwBytesRead == 0)
        {
            break;
        }

        // hash some data
        if (!NT_SUCCESS(hashStatus = BCryptHashData(hHash, (PBYTE)buffer, dwBytesRead, 0)))
        {
            if (!args->status)
            {
                printf("data hashing failed: %ld\n", hashStatus);
            }
            status = CALC_HASH_FAILED_TO_HASH;
            goto Cleanup;
        }
    }

    // close the hash
    if (!NT_SUCCESS(hashStatus = BCryptFinishHash(hHash, pbHash, cbHash, 0)))
    {
        if (!args->status)
        {
            printf("hash finalization failed: %ld\n", hashStatus);
        }
        status = CALC_HASH_FAILED_TO_FINISH_HASH;
        goto Cleanup;
    }

    // Output the hash
    *file_hash = malloc((cbHash * 2 + 1) * sizeof(WCHAR));
    if (*file_hash == NULL)
    {
        if (!args->status)
        {
            printf("memory allocation for file hash failed\n");
        }
        status = CALC_HASH_FAILED_TO_ALLOCATE_FILE_HASH;
        goto Cleanup;
    }

    for (DWORD i = 0; i < cbHash; i++)
    {
        swprintf_s((*file_hash) + i * 2, 3, L"%02x", pbHash[i]);
    }
    (*file_hash)[cbHash * 2] = L'\0';

Cleanup:

    if (hFile)
    {
        CloseHandle(hFile);
    }

    if (hAlg)
    {
        BCryptCloseAlgorithmProvider(hAlg, 0);
    }

    if (hHash)
    {
        BCryptDestroyHash(hHash);
    }

    if (pbHashObject)
    {
        HeapFree(GetProcessHeap(), 0, pbHashObject);
    }

    if (pbHash)
    {
        HeapFree(GetProcessHeap(), 0, pbHash);
    }

    if (status != SUCCESS)
    {
        *file_hash = NULL;
    }

    return status;
}

ErrorCode PrintHash(__in Args* args, __in LPWSTR file)
{
    LPWSTR hash = NULL;
    ErrorCode ok = CalcHash(args, &hash, file);
    if (hash != NULL && ok == SUCCESS)
    {
        wprintf(L"%ls *%ls\n", hash, file);
    }
    return ok;
}

ErrorCode ParseLine(__in Args* args, __out FileHash* fh, __in int line_num, __in LPWSTR line)
{
    LPWSTR tokContext = NULL;
    LPWSTR delim = L" ";

    fh->hash = wcstok_s(line, delim, &tokContext);
    if (fh->hash == NULL)
    {
        if (!args->status && args->warn)
        {
            printf("invalid hash on line %d\n", line_num);
        }
        return PARSE_LINE_INVALID_HASH_TOKEN;
    }

    if (wcslen(fh->hash) != HASH_LENGTH)
    {
        if (!args->status && args->warn)
        {
            printf("invalid hash on line %d\n", line_num);
        }
        return PARSE_LINE_INVALID_HASH_LENGTH;
    }

    fh->file = wcstok_s(NULL, delim, &tokContext);
    if (fh->file == NULL)
    {
        if (!args->status && args->warn)
        {
            printf("invalid file on line %d\n", line_num);
        }
        return PARSE_LINE_INAVLID_FILE;
    }

    return SUCCESS;
}

ErrorCode VerifyChecksums(__in Args* args)
{
    ErrorCode status = SUCCESS;
    HANDLE hFile = NULL;
    CHAR buffer[LINE_BUFFER_SIZE] = { 0 };
    CHAR lineBuffer[LINE_BUFFER_SIZE] = { 0 };
    DWORD dwBytesRead;
    UINT lineIndex = 0;
    int lineNum = 1;
    FileHash* head = NULL;
    FileHash* current = NULL;

    // open file
    hFile = CreateFileW(args->sumFile,        // File name
                        GENERIC_READ,          // Open for reading
                        0,                     // No sharing
                        NULL,                  // Default security
                        OPEN_EXISTING,         // Existing file only
                        FILE_ATTRIBUTE_NORMAL, // Normal file
                        NULL);
    if (hFile == INVALID_HANDLE_VALUE)
    {
        if (!args->status)
        {
            printf("failed to open file: %lu\n", GetLastError());
        }
        status = CHECK_SUMS_FAILED_TO_OPEN_SUM_FILE;
        goto Cleanup;
    }

    while (ReadFile(hFile, buffer, LINE_BUFFER_SIZE, &dwBytesRead, NULL) && dwBytesRead > 0)
    {
        for (UINT i = 0; i < dwBytesRead; i++)
        {
            if (buffer[i] != '\n')
            {
                if (lineIndex < LINE_BUFFER_SIZE - 1)
                {
                    lineBuffer[lineIndex++] = buffer[i];
                }
                else
                {
                    if (!args->status)
                    {
                        printf("line %d too long, max size: %d\n", lineNum, LINE_BUFFER_SIZE);
                    }
                    status = CHECK_SUMS_LINE_TOO_LONG;
                    goto Cleanup;
                }
            }
            else
            {
                // check if \r is at the end and replace it with \0
                if (lineIndex > 0 && lineBuffer[lineIndex - 1] == '\r')
                {
                    lineBuffer[lineIndex - 1] = '\0';
                }
                // add \0 in case there was no \r
                lineBuffer[lineIndex] = '\0';

                int reqSize = MultiByteToWideChar(CP_UTF8, 0, lineBuffer, lineIndex, NULL, 0);
                LPWSTR wideBuffer = malloc(sizeof(WCHAR) * (reqSize + 1));
                if (wideBuffer == NULL)
                {
                    if (!args->status)
                    {
                        printf("failed to allocate memory for wideBuffer1 for line %d\n", lineNum);
                    }
                    status = CHECK_SUMS_FAILED_TO_ALLOCATE_WIDE_BUFFER1;
                    goto Cleanup;
                }
                MultiByteToWideChar(CP_UTF8, 0, lineBuffer, lineIndex, wideBuffer, reqSize);
                wideBuffer[reqSize] = L'\0';

                FileHash* fh = malloc(sizeof(FileHash));
                if (fh == NULL)
                {
                    if (!args->status)
                    {
                        printf("failed to allocate memory for fh1 for line %d\n", lineNum);
                    }
                    status = CHECK_SUMS_FAILED_TO_ALLOCATE_FILE_HASH1;
                    goto Cleanup;
                }
                fh->next = NULL;

                if (reqSize == 0 || wcslen(wideBuffer) == 0)
                {
                    if (!args->status)
                    {
                        printf("skip empty line %d\n", lineNum);
                    }
                    free(fh);
                }
                else
                {
                    ErrorCode parseResult = ParseLine(args, fh, lineNum, wideBuffer);
                    if (parseResult != SUCCESS)
                    {
                        free(fh);
                        status = parseResult;
                        goto Cleanup;
                    }
                    else
                    {
                        if (head == NULL)
                        {
                            head = fh;
                        }
                        else
                        {
                            current->next = fh;
                        }
                        current = fh;
                    }
                }

                lineIndex = 0;
                lineNum++;
            }
        }
    }

    // last line withtout trailing line break
    if (lineIndex > 0)
    {
        if (lineBuffer[lineIndex - 1] == '\r')
        {
            lineBuffer[lineIndex - 1] = '\0';
        }
        lineBuffer[lineIndex] = '\0';

        int reqSize = MultiByteToWideChar(CP_UTF8, 0, lineBuffer, lineIndex, NULL, 0);
        LPWSTR wideBuffer = malloc(sizeof(WCHAR) * (reqSize + 1));
        if (wideBuffer == NULL)
        {
            if (!args->status)
            {
                printf("failed to allocate memory for wideBuffer2 for line %d\n", lineNum);
            }
            status = CHECK_SUMS_FAILED_TO_ALLOCATE_WIDE_BUFFER2;
            goto Cleanup;
        }
        MultiByteToWideChar(CP_UTF8, 0, lineBuffer, lineIndex, wideBuffer, reqSize);
        wideBuffer[reqSize] = L'\0';

        FileHash* fh = malloc(sizeof(struct file_hash_t));
        if (fh == NULL)
        {
            if (!args->status)
            {
                printf("failed to allocate memory for fh2 for line %d\n", lineNum);
            }
            status = CHECK_SUMS_FAILED_TO_ALLOCATE_FILE_HASH2;
            goto Cleanup;
        }
        fh->next = NULL;

        if (reqSize == 0 || wcslen(wideBuffer) == 0)
        {
            if (!args->status)
            {
                printf("skip empty line %d\n", lineNum);
            }
        }
        else
        {
            ErrorCode parseResult = ParseLine(args, fh, lineNum, wideBuffer);
            if (parseResult != SUCCESS)
            {
                free(fh);
                status = parseResult;
                goto Cleanup;
            }
            else
            {
                if (head == NULL)
                {
                    head = fh;
                }
                else
                {
                    current->next = fh;
                }
                current = fh;
            }
        }
    }

    if (GetLastError() != 0)
    {
        if (!args->status)
        {
            printf("file read failed: %lu\n", GetLastError());
        }
        status = CHECK_SUMS_FAILED_TO_READ;
        goto Cleanup;
    }

    current = head;
    while (current != NULL)
    {
        LPWSTR file_hash = NULL;
        ErrorCode calcResult = CalcHash(args, &file_hash, current->file);
        if (calcResult != SUCCESS)
        {
            status = calcResult;
            goto Cleanup;
        }

        wchar_t msg[MAX_PATH + 20];
        if (wcscmp(current->hash, file_hash) == 0)
        {
            if (!args->status && !args->quiet)
            {
                wsprintfW(msg, L"%ls: OK\r\n", current->file);
                WriteConsoleW(GetStdHandle(STD_OUTPUT_HANDLE), msg, lstrlenW(msg), NULL, NULL);
            }
        }
        else
        {
            if (!args->status)
            {
                wsprintfW(msg, L"%ls: FAILED\r\n", current->file);
                WriteConsoleW(GetStdHandle(STD_OUTPUT_HANDLE), msg, lstrlenW(msg), NULL, NULL);
            }
            status = CHECK_SUM_CHECKSUM_FAILED;
        }

        current = current->next;
    }

    if (!args->status && status == CHECK_SUM_CHECKSUM_FAILED)
    {
        LPWSTR msg = L"checksum failed\r\n";
        WriteConsoleW(GetStdHandle(STD_OUTPUT_HANDLE), msg, lstrlenW(msg), NULL, NULL);
    }

Cleanup:
    if (hFile)
    {
        CloseHandle(hFile);
    }

    // clean file_hashes
    if (head != NULL)
    {
        current = head;
        FileHash* next = NULL;
        while (current != NULL)
        {
            next = current->next;
            free(current);
            current = next;
        }
    }

    return status;
}
