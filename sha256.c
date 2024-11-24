#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "Shlwapi.lib")

#include <strsafe.h>
#include <shlwapi.h>
#include <bcrypt.h>

#include "sha256sum.h"

#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#define STATUS_UNSUCCESSFUL ((NTSTATUS)0xC0000001L)

#define HASH_LENGTH 64
#define LINE_BUFFER_SIZE 1024
#define MAX_PRINT_MSG_LENGTH 200

WCHAR msg[1024];

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
    hFile = CreateFileW(file,
                        GENERIC_READ,
                        FILE_SHARE_READ,
                        NULL,                  // Default security
                        OPEN_EXISTING,
                        FILE_ATTRIBUTE_NORMAL,
                        NULL);
    if (hFile == INVALID_HANDLE_VALUE)
    {
        if (!args->status)
        {
            HRESULT hr = StringCchPrintfW(msg,
                                          _countof(msg),  // Size of buffer in characters
                                          L"failed to open file '%ls' with error: %lu\r\n",
                                          file, GetLastError());
            if (SUCCEEDED(hr))
            {
                WriteConsoleW(GetStdHandle(STD_ERROR_HANDLE), msg, lstrlenW(msg), NULL, NULL);
            }
        }
        status = CALC_HASH_FAILED_TO_OPEN_FILE;
        goto Cleanup;
    }

    // open an algorithm handle
    if (!NT_SUCCESS(hashStatus = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL, 0)))
    {
        if (!args->status)
        {
            HRESULT hr = StringCchPrintfW(msg,
                                          _countof(msg),
                                          L"open an algorithm handle failed: %ld\r\n",
                                          hashStatus);
            if (SUCCEEDED(hr))
            {
                WriteConsoleW(GetStdHandle(STD_ERROR_HANDLE), msg, lstrlenW(msg), NULL, NULL);
            }
        }
        status = CALC_HASH_FAILED_TO_OPEN_ALG_HANDLE;
        goto Cleanup;
    }

    // calculate the size of the buffer to hold the hash object
    if (!NT_SUCCESS(hashStatus = BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PBYTE)&cbHashObject, sizeof(DWORD), &cbData, 0)))
    {
        if (!args->status)
        {
            HRESULT hr = StringCchPrintfW(msg,
                                          _countof(msg),
                                          L"hash buffer size allocation failed, err: %ld\r\n",
                                          hashStatus);
            if (SUCCEEDED(hr))
            {
                WriteConsoleW(GetStdHandle(STD_ERROR_HANDLE), msg, lstrlenW(msg), NULL, NULL);
            }
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
            HRESULT hr = StringCchPrintfW(msg,
                                          _countof(msg),
                                          L"memory allocation for hash object failed\r\n");
            if (SUCCEEDED(hr))
            {
                WriteConsoleW(GetStdHandle(STD_ERROR_HANDLE), msg, lstrlenW(msg), NULL, NULL);
            }
        }
        status = CALC_HASH_FAILED_TO_ALLOCATE_HASH_OBJECT;
        goto Cleanup;
    }

    // calculate the length of the hash
    if (!NT_SUCCESS(hashStatus = BCryptGetProperty(hAlg, BCRYPT_HASH_LENGTH, (PBYTE)&cbHash, sizeof(DWORD), &cbData, 0)))
    {
        if (!args->status)
        {
            HRESULT hr = StringCchPrintfW(msg,
                                          _countof(msg),
                                          L"hash length calculation failed: %ld\r\n",
                                          hashStatus);
            if (SUCCEEDED(hr))
            {
                WriteConsoleW(GetStdHandle(STD_ERROR_HANDLE), msg, lstrlenW(msg), NULL, NULL);
            }
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
            HRESULT hr = StringCchPrintfW(msg,
                                          _countof(msg),
                                          L"memory allocation for hash buffer failed\r\n");
            if (SUCCEEDED(hr))
            {
                WriteConsoleW(GetStdHandle(STD_ERROR_HANDLE), msg, lstrlenW(msg), NULL, NULL);
            }
        }
        status = CALC_HASH_FAILED_TO_ALLOCATE_HASH_BUFFER;
        goto Cleanup;
    }

    // create a hash
    if (!NT_SUCCESS(hashStatus = BCryptCreateHash(hAlg, &hHash, pbHashObject, cbHashObject, NULL, 0, 0)))
    {
        if (!args->status)
        {
            HRESULT hr = StringCchPrintfW(msg,
                                          _countof(msg),
                                          L"hash creation failed: %ld\r\n",
                                          hashStatus);
            if (SUCCEEDED(hr))
            {
                WriteConsoleW(GetStdHandle(STD_ERROR_HANDLE), msg, lstrlenW(msg), NULL, NULL);
            }
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
                HRESULT hr = StringCchPrintfW(msg,
                                              _countof(msg),
                                              L"read file failed: %lu\r\n",
                                              GetLastError());
                if (SUCCEEDED(hr))
                {
                    WriteConsoleW(GetStdHandle(STD_ERROR_HANDLE), msg, lstrlenW(msg), NULL, NULL);
                }
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
                HRESULT hr = StringCchPrintfW(msg,
                                              _countof(msg),
                                              L"data hashing failed: %ld\r\n",
                                              hashStatus);
                if (SUCCEEDED(hr))
                {
                    WriteConsoleW(GetStdHandle(STD_ERROR_HANDLE), msg, lstrlenW(msg), NULL, NULL);
                }
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
            HRESULT hr = StringCchPrintfW(msg,
                                          _countof(msg),
                                          L"hash finalization failed: %ld\r\n",
                                          hashStatus);
            if (SUCCEEDED(hr))
            {
                WriteConsoleW(GetStdHandle(STD_ERROR_HANDLE), msg, lstrlenW(msg), NULL, NULL);
            }
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
            HRESULT hr = StringCchPrintfW(msg,
                                          _countof(msg),
                                          L"memory allocation for file hash failed\r\n");
            if (SUCCEEDED(hr))
            {
                WriteConsoleW(GetStdHandle(STD_ERROR_HANDLE), msg, lstrlenW(msg), NULL, NULL);
            }
        }
        status = CALC_HASH_FAILED_TO_ALLOCATE_FILE_HASH;
        goto Cleanup;
    }

    for (DWORD i = 0; i < cbHash; i++)
    {
        StringCchPrintfW((*file_hash) + i * 2, 3, L"%02x", pbHash[i]);
    }

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

void WriteFileUTF8(__in HANDLE handle, __in LPWSTR msg)
{
    int utf8Size = WideCharToMultiByte(CP_UTF8, 0, msg, -1, NULL, 0, NULL, NULL);
    if (utf8Size > 0)
    {
        LPSTR utf8Msg = (LPSTR)malloc(utf8Size);
        if (utf8Msg)
        {
            // convert UTF-16 to UTF-8
            WideCharToMultiByte(CP_UTF8, 0, msg, -1, utf8Msg, utf8Size, NULL, NULL);
            WriteFile(handle, utf8Msg, utf8Size - 1, NULL, NULL); // -1, um das Nullterminierungszeichen nicht zu schreiben
            free(utf8Msg);
        }
    }
}

ErrorCode PrintHash(__in Args* args, __in LPWSTR userInputFilePath, __in LPWSTR fileName)
{
    // get full path from user input path, remove the file and append fileName so we get
    // a clean absolute file path
    WCHAR absPath[MAX_PATH];
    if (GetFullPathNameW(userInputFilePath, MAX_PATH, absPath, NULL) == 0 || absPath == NULL)
    {
        return PRINT_HASH_FAILED_GET_FULL_PATH_NAME;
    }

    PathRemoveFileSpecW(absPath);

    WCHAR absFilePath[MAX_PATH];
    PathCombineW(absFilePath, absPath, fileName);

    // now calculate the file hash using the absolute file path we just constructed
    LPWSTR hash = NULL;
    ErrorCode ok = CalcHash(args, &hash, absFilePath);
    if (hash != NULL && ok == SUCCESS)
    {
        // depending whether it is a relative or an absolute path the output needs to be different to
        // immitade the output of sha256sum from Linux
        BOOL isRel = PathIsRelativeW(userInputFilePath);
        if (isRel == TRUE)
        {
            size_t userInputFilePathLen;
            if (FAILED(StringCchLengthW(userInputFilePath, MAX_PATH, &userInputFilePathLen)))
            {
                return PRINT_HASH_FAILED_STRING_LENGTH;
            }
            WCHAR inputPath[MAX_PATH];
            BOOL containsPath = PathRemoveFileName(inputPath, userInputFilePath);

            // if the user passed a relative file without a .\ or ..\ and other prefixes
            if (containsPath == FALSE)
            {
                HRESULT hr = StringCchPrintfW(msg,
                                              _countof(msg),
                                              L"%ls *%ls\r\n",
                                              hash, fileName);
                if (FAILED(hr))
                {
                    return PRINT_HASH_FAILED_STRING_CAT3;
                }
                HANDLE handle = GetStdHandle(STD_OUTPUT_HANDLE);
                DWORD mode;
                if (GetConsoleMode(handle, &mode))
                {
                    WriteConsoleW(handle, msg, lstrlenW(msg), NULL, NULL);
                }
                else // redirect
                {
                    WriteFileUTF8(handle, msg);
                }
            }
            // if the user passed a relative file with .\, ..\ and so on, we
            // need to concatenate the inputFilePath and the given fileName
            else
            {
                WCHAR inputFilePath[MAX_PATH] = { 0 };
                StringCchCopyW(inputFilePath, MAX_PATH, inputPath);

                WCHAR separator = PathFindSeparator(userInputFilePath, userInputFilePathLen);
                size_t len = lstrlenW(inputFilePath);
                if (len+1 > MAX_PATH)
                {
                    return PRINT_HASH_FAILED_STRING_CAT1;
                }
                inputFilePath[len] = separator;

                if (FAILED(StringCchCatW(inputFilePath, MAX_PATH, fileName)))
                {
                    return PRINT_HASH_FAILED_STRING_CAT2;
                }

                HRESULT hr = StringCchPrintfW(msg,
                                              _countof(msg),
                                              L"%ls *%ls\r\n",
                                              hash, inputFilePath);
                if (FAILED(hr))
                {
                    return PRINT_HASH_FAILED_STRING_CAT4;
                }
                HANDLE handle = GetStdHandle(STD_OUTPUT_HANDLE);
                DWORD mode;
                if (GetConsoleMode(handle, &mode))
                {
                    WriteConsoleW(handle, msg, lstrlenW(msg), NULL, NULL);
                } else // redirect
                {
                    WriteFileUTF8(handle, msg);
                }
            }
        }
        // in case of an absolute path the absolute path shall be used
        else
        {
            HRESULT hr = StringCchPrintfW(msg,
                                          _countof(msg),
                                          L"%ls *%ls\r\n",
                                          hash, absFilePath);
            if (FAILED(hr))
            {
                return PRINT_HASH_FAILED_STRING_CAT5;
            }
            HANDLE handle = GetStdHandle(STD_OUTPUT_HANDLE);
            DWORD mode;
            if (GetConsoleMode(handle, &mode))
            {
                WriteConsoleW(handle, msg, lstrlenW(msg), NULL, NULL);
            }
            else // redirect
            {
                WriteFileUTF8(handle, msg);
            }
        }
    }
    return SUCCESS;
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
            HRESULT hr = StringCchPrintfW(msg,
                                          _countof(msg),
                                          L"invalid hash on line %d\r\n",
                                          line_num);
            if (SUCCEEDED(hr))
            {
                WriteConsoleW(GetStdHandle(STD_ERROR_HANDLE), msg, lstrlenW(msg), NULL, NULL);
            }
        }
        return PARSE_LINE_INVALID_HASH_TOKEN;
    }

    if (wcslen(fh->hash) != HASH_LENGTH)
    {
        if (!args->status && args->warn)
        {
            HRESULT hr = StringCchPrintfW(msg,
                                          _countof(msg),
                                          L"invalid hash on line %d\r\n",
                                          line_num);
            if (SUCCEEDED(hr))
            {
                WriteConsoleW(GetStdHandle(STD_ERROR_HANDLE), msg, lstrlenW(msg), NULL, NULL);
            }
        }
        return PARSE_LINE_INVALID_HASH_LENGTH;
    }

    fh->file = wcstok_s(NULL, delim, &tokContext);
    if (fh->file == NULL)
    {
        if (!args->status && args->warn)
        {
            HRESULT hr = StringCchPrintfW(msg,
                                          _countof(msg),
                                          L"invalid hash on line %d\r\n",
                                          line_num);
            if (SUCCEEDED(hr))
            {
                WriteConsoleW(GetStdHandle(STD_ERROR_HANDLE), msg, lstrlenW(msg), NULL, NULL);
            }
        }
        return PARSE_LINE_INAVLID_FILE;
    }

    return SUCCESS;
}

BOOL IsUTF16File(LPCWSTR filePath)
{
    BOOL isUTF16 = FALSE;
    HANDLE hFile = CreateFileW(filePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

    if (hFile != INVALID_HANDLE_VALUE)
    {
        BYTE bom[2];
        DWORD bytesRead;

        if (ReadFile(hFile, bom, sizeof(bom), &bytesRead, NULL))
        {
            // check for UTF-16 header
            if ((bom[0] == 0xFF && bom[1] == 0xFE) || (bom[0] == 0xFE && bom[1] == 0xFF))
            {
                isUTF16 = TRUE;
            }
        }

        CloseHandle(hFile);
    }

    return isUTF16;
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

    BOOL isUTF16 = IsUTF16File(args->sumFile);
    if (isUTF16)
    {
        return CHECK_SUMS_FAILED_UNSUPPORTED_UTF_16;
    }

    // open file
    hFile = CreateFileW(args->sumFile,         // File name
                        GENERIC_READ,          // Open for reading
                        FILE_SHARE_READ,       // No sharing
                        NULL,                  // Default security
                        OPEN_EXISTING,         // Existing file only
                        FILE_ATTRIBUTE_NORMAL, // Normal file
                        NULL);
    if (hFile == INVALID_HANDLE_VALUE)
    {
        if (!args->status)
        {
            HRESULT hr = StringCchPrintfW(msg,
                                          _countof(msg),
                                          L"failed to open file: %lu\r\n",
                                          GetLastError());
            if (SUCCEEDED(hr))
            {
                WriteConsoleW(GetStdHandle(STD_ERROR_HANDLE), msg, lstrlenW(msg), NULL, NULL);
            }
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
                        HRESULT hr = StringCchPrintfW(msg,
                                                      _countof(msg),
                                                      L"line %d too long, max size: %du\r\n",
                                                      lineNum, LINE_BUFFER_SIZE);
                        if (SUCCEEDED(hr))
                        {
                            WriteConsoleW(GetStdHandle(STD_ERROR_HANDLE), msg, lstrlenW(msg), NULL, NULL);
                        }
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
                        HRESULT hr = StringCchPrintfW(msg,
                                                      _countof(msg),
                                                      L"failed to allocate memory for wideBuffer1 for line %d\r\n",
                                                      lineNum);
                        if (SUCCEEDED(hr))
                        {
                            WriteConsoleW(GetStdHandle(STD_ERROR_HANDLE), msg, lstrlenW(msg), NULL, NULL);
                        }
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
                        HRESULT hr = StringCchPrintfW(msg,
                                                      _countof(msg),
                                                      L"failed to allocate memory for fh1 for line %d\r\n",
                                                      lineNum);
                        if (SUCCEEDED(hr))
                        {
                            WriteConsoleW(GetStdHandle(STD_ERROR_HANDLE), msg, lstrlenW(msg), NULL, NULL);
                        }
                    }
                    status = CHECK_SUMS_FAILED_TO_ALLOCATE_FILE_HASH1;
                    goto Cleanup;
                }
                fh->next = NULL;

                if (reqSize == 0 || wcslen(wideBuffer) == 0)
                {
                    if (!args->status)
                    {
                        HRESULT hr = StringCchPrintfW(msg,
                                                      _countof(msg),
                                                      L"skip empty line %d\r\n",
                                                      lineNum);
                        if (SUCCEEDED(hr))
                        {
                            WriteConsoleW(GetStdHandle(STD_ERROR_HANDLE), msg, lstrlenW(msg), NULL, NULL);
                        }
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
                HRESULT hr = StringCchPrintfW(msg,
                                              _countof(msg),
                                              L"failed to allocate memory for wideBuffer2 for line %d\r\n",
                                              lineNum);
                if (SUCCEEDED(hr))
                {
                    WriteConsoleW(GetStdHandle(STD_ERROR_HANDLE), msg, lstrlenW(msg), NULL, NULL);
                }
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
                HRESULT hr = StringCchPrintfW(msg,
                                              _countof(msg),
                                              L"failed to allocate memory for fh2 for line %d\r\n",
                                              lineNum);
                if (SUCCEEDED(hr))
                {
                    WriteConsoleW(GetStdHandle(STD_ERROR_HANDLE), msg, lstrlenW(msg), NULL, NULL);
                }
            }
            status = CHECK_SUMS_FAILED_TO_ALLOCATE_FILE_HASH2;
            goto Cleanup;
        }
        fh->next = NULL;

        if (reqSize == 0 || wcslen(wideBuffer) == 0)
        {
            if (!args->status)
            {
                HRESULT hr = StringCchPrintfW(msg,
                                              _countof(msg),
                                              L"skip empty line %d\r\n",
                                              lineNum);
                if (SUCCEEDED(hr))
                {
                    WriteConsoleW(GetStdHandle(STD_ERROR_HANDLE), msg, lstrlenW(msg), NULL, NULL);
                }
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
            HRESULT hr = StringCchPrintfW(msg,
                                          _countof(msg),
                                          L"file read failed: %lu\r\n",
                                          GetLastError());
            if (SUCCEEDED(hr))
            {
                WriteConsoleW(GetStdHandle(STD_ERROR_HANDLE), msg, lstrlenW(msg), NULL, NULL);
            }
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

        if (wcscmp(current->hash, file_hash) == 0)
        {
            if (!args->status && !args->quiet)
            {
                HRESULT hr = StringCchPrintfW(msg,
                                              _countof(msg),
                                              L"%ls: OK\r\n",
                                              current->file);
                if (SUCCEEDED(hr))
                {
                    WriteConsoleW(GetStdHandle(STD_OUTPUT_HANDLE), msg, lstrlenW(msg), NULL, NULL);
                }
            }
        }
        else
        {
            if (!args->status)
            {
                HRESULT hr = StringCchPrintfW(msg,
                                              _countof(msg),
                                              L"%ls: FAILED\r\n", 
                                              current->file);
                if (SUCCEEDED(hr))
                {
                    WriteConsoleW(GetStdHandle(STD_OUTPUT_HANDLE), msg, lstrlenW(msg), NULL, NULL);
                }
            }
            status = CHECK_SUM_CHECKSUM_FAILED;
        }

        current = current->next;
    }

    if (!args->status && status == CHECK_SUM_CHECKSUM_FAILED)
    {
        HRESULT hr = StringCchPrintfW(msg,
                                      _countof(msg),
                                      L"checksum failed\r\n");
        if (SUCCEEDED(hr))
        {
            WriteConsoleW(GetStdHandle(STD_OUTPUT_HANDLE), msg, lstrlenW(msg), NULL, NULL);
        }
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

WCHAR PathFindSeparator(__in LPWSTR filePath, __in size_t filePathLen)
{
    for (size_t i = 0; i < filePathLen; i++)
    {
        if (filePath[i] == L'/' || filePath[i] == L'\\')
        {
            return filePath[i];
        }
    }
    return L'\\'; // return windows default if none found
}

BOOL PathRemoveFileName(__out_ecount(MAX_PATH) LPWSTR dst, __in LPWSTR src)
{
    LPWSTR lastSlash = wcsrchr(src, L'/');
    LPWSTR lastBackslash = wcsrchr(src, L'\\');

    // If no path separator was found this function fails
    if (lastSlash == NULL && lastBackslash == NULL)
    {
        StringCchCopyW(dst, MAX_PATH, L"");
        return FALSE;
    }

    LPWSTR lastSeparator = (lastSlash > lastBackslash) ? lastSlash : lastBackslash;
    size_t length = lastSeparator - src;
    HRESULT hr = StringCchCopyNW(dst, length + 1, src, length);
    return SUCCEEDED(hr) ? TRUE : FALSE;
}
