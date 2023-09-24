#include <windows.h>
#include <stdio.h>
#include <bcrypt.h>

#pragma comment(lib, "bcrypt.lib")

#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#define STATUS_UNSUCCESSFUL ((NTSTATUS)0xC0000001L)
#define SET_FAILURE_AND_CLEANUP do { \
    failure = TRUE;                       \
    goto Cleanup;                         \
} while(0)

int __cdecl wmain(int argc, wchar_t *argv[])
{
  BOOL failure = FALSE;
  HANDLE hFile;
  DWORD dwBytesRead;
  BYTE buffer[1024] = {0};

  BCRYPT_ALG_HANDLE hAlg = NULL;
  BCRYPT_HASH_HANDLE hHash = NULL;
  NTSTATUS status = STATUS_UNSUCCESSFUL;
  DWORD cbData = 0,
        cbHash = 0,
        cbHashObject = 0;
  PBYTE pbHashObject = NULL;
  PBYTE pbHash = NULL;

  // read args
  if (argc < 2)
  {
    wprintf(L"missing file parameter\n");
    wprintf(L"usage: %ls <filename>\n", argv[0]);
    return 1;
  }

  // open file
  hFile = CreateFileW(argv[1],               // File name
                      GENERIC_READ,          // Open for reading
                      0,                     // No sharing
                      NULL,                  // Default security
                      OPEN_EXISTING,         // Existing file only
                      FILE_ATTRIBUTE_NORMAL, // Normal file
                      NULL);
  if (hFile == INVALID_HANDLE_VALUE)
  {
    wprintf(L"open file failed: %d\n", GetLastError());
    SET_FAILURE_AND_CLEANUP;
  }

  // open an algorithm handle
  if (!NT_SUCCESS(status = BCryptOpenAlgorithmProvider(
                      &hAlg,
                      BCRYPT_SHA256_ALGORITHM,
                      NULL,
                      0)))
  {
    wprintf(L"open an algorithm handle failed: %x\n", status);
    SET_FAILURE_AND_CLEANUP;
  }

  // calculate the size of the buffer to hold the hash object
  if (!NT_SUCCESS(status = BCryptGetProperty(
                      hAlg,
                      BCRYPT_OBJECT_LENGTH,
                      (PBYTE)&cbHashObject,
                      sizeof(DWORD),
                      &cbData,
                      0)))
  {
    wprintf(L"hash buffer size allocation failed, err: %x\n", status);
    SET_FAILURE_AND_CLEANUP;
  }

  // allocate the hash object on the heap
  pbHashObject = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbHashObject);
  if (NULL == pbHashObject)
  {
    wprintf(L"memory allocation for hash object failed\n");
    SET_FAILURE_AND_CLEANUP;
  }

  // calculate the length of the hash
  if (!NT_SUCCESS(status = BCryptGetProperty(
                      hAlg,
                      BCRYPT_HASH_LENGTH,
                      (PBYTE)&cbHash,
                      sizeof(DWORD),
                      &cbData,
                      0)))
  {
    wprintf(L"hash length calculation failed: %x\n", status);
    SET_FAILURE_AND_CLEANUP;
  }

  // allocate the hash buffer on the heap
  pbHash = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbHash);
  if (NULL == pbHash)
  {
    wprintf(L"memory allocation for hash buffer failed\n");
    SET_FAILURE_AND_CLEANUP;
  }

  // create a hash
  if (!NT_SUCCESS(status = BCryptCreateHash(
                      hAlg,
                      &hHash,
                      pbHashObject,
                      cbHashObject,
                      NULL,
                      0,
                      0)))
  {
    wprintf(L"hash creation failed: %x\n", status);
    SET_FAILURE_AND_CLEANUP;
  }

  while (TRUE)
  {
    if (!ReadFile(hFile, buffer, sizeof(buffer), &dwBytesRead, NULL))
    {
      wprintf(L"read file failed: %d\n", GetLastError());
      SET_FAILURE_AND_CLEANUP;
    }

    if (dwBytesRead == 0)
    {
      break;
    }

    // hash some data
    if (!NT_SUCCESS(status = BCryptHashData(
                        hHash,
                        (PBYTE)buffer,
                        dwBytesRead,
                        0)))
    {
      wprintf(L"data hashing failed: %x\n", status);
      SET_FAILURE_AND_CLEANUP;
    }
  }

  // close the hash
  if (!NT_SUCCESS(status = BCryptFinishHash(
                      hHash,
                      pbHash,
                      cbHash,
                      0)))
  {
    wprintf(L"hash finalization failed: %x\n", status);
    SET_FAILURE_AND_CLEANUP;
  }

  // Output the hash
  for (DWORD i = 0; i < cbHash; i++)
  {
    printf("%02x", pbHash[i]);
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

  return failure;
}
