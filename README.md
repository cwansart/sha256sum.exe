# sha256sum for Windows

The built-in certutil utility in CMD is not ideal for use in a Dockerfile, primarily because it prints out multiple lines and lacks a -c option for file verification. To avoid relying on third-party solutions from unknown authors, I've created my own sha256sum.exe utility.

## Requirements

The _Makefile_ is designed for use with MSVC. Specifically, I've developed it using VS 2022 version v17.7.4.

## Building sha256sum.exe

1. Open the _x64 Native Tools Command Prompt for VS 2022_.
2. Navigate to the folder containing the Makefile.
3. Run the `msbuild` command.

Alternatively, you can open the Solution file in the Visual Studio IDE.

## Usage

```bash
sha256sum [OPTION]... [FILE]...
```

| Option             | Description                                                                             |
| ------------------ | --------------------------------------------------------------------------------------- |
| -c, --check <FILE> | read checksums from the FILE and check them, input must be UTF-8 encoded                |
| -b, --binary       | read in binary mode, this is default                                                    |
| -t, --text         | read in text mode, fails because WinAPI's ReadFile/CreateFile only reads in binary mode |
| -q, --quiet        | don't print OK, just FAILED if checks fail                                              |
| -s, --status       | don't print anything, just return status code                                           |
| -w, --warn         | shows SHA256SUMS errors                                                                 |
| -v, --version      | shows program's version                                                                 |

### Examples

Here's how to use the utility:

```bash
sha256sum.exe myText.txt
sha256sum.exe *.txt
sha256sum.exe hello.txt world.txt
sha256sum.exe *.txt > SHA256SUMS
sha256sum.exe -c SHA256SUMS
```

### Exit Codes

| Code | Name                                          | Description                                                                |
| ---- | --------------------------------------------- | -------------------------------------------------------------------------- |
| 1    | MAIN_FAILED_TO_FIND_FILES                     | WinAPI's FindFirstFile was not able to find files wth given FILE arguments |
| 2    | PARSE_ARGS_MISSING_PARAMETER                  | too few arguments, at least 1 is required                                  |
| 3    | PARSE_ARGS_MISSING_SHASUMS_FILE               | -c argument found but missing following sum file, `-c <FILE>`              |
| 4    | PARSE_ARGS_ALLOCATE_ERROR                     | memory allocation failed for file list, memory low?                        |
| 5    | CALC_HASH_FAILED_TO_OPEN_FILE                 | failed to open FILE, check permissions, if file exists                     |
| 6    | CALC_HASH_FAILED_TO_OPEN_ALG_HANDLE           | failed to open algorithm handle[1]                                         |
| 7    | CALC_HASH_FAILED_TO_ALLOCATE_HASH_BUFFER_SIZE | failed to calculate hash buffer size[1]                                    |
| 8    | CALC_HASH_FAILED_TO_ALLOCATE_HASH_OBJECT      | failed to allocate hash object[1]                                          |
| 9    | CALC_HASH_FAILED_TO_CALC_HASH_LENGTH          | failed to calculate hash length[1]                                         |
| 10   | CALC_HASH_FAILED_TO_ALLOCATE_HASH_BUFFER      | failed to allocate hash buffer[1]                                          |
| 11   | CALC_HASH_FAILED_TO_CREATE_HASH               | failed to create hash[1]                                                   |
| 12   | CALC_HASH_FAILED_TO_READ                      | failed to read from given FILE                                             |
| 13   | CALC_HASH_FAILED_TO_HASH                      | failed to hash[1]                                                          |
| 14   | CALC_HASH_FAILED_TO_FINISH_HASH               | failed to finish hash[1]                                                   |
| 15   | CALC_HASH_FAILED_TO_ALLOCATE_FILE_HASH        | failed to allocate memory for file hash, check your memory                 |
| 16   | PARSE_LINE_INVALID_HASH_TOKEN                 | invalid hash token may happen if the line does not contain spaces          |
| 17   | PARSE_LINE_INVALID_HASH_LENGTH                | fails when the token is not 64 characters long                             |
| 18   | PARSE_LINE_INAVLID_FILE                       | fails if the file does not have a second string after the space(s)         |
| 19   | CHECK_SUMS_FAILED_TO_OPEN_SUM_FILE            | failed to open -c FILE                                                     |
| 20   | CHECK_SUMS_LINE_TOO_LONG                      | line in sum file is longer exceeds internal buffer (1024)                  |
| 21   | CHECK_SUMS_FAILED_TO_ALLOCATE_WIDE_BUFFER1    | line buffer allocation for UTF-16 failed                                   |
| 22   | CHECK_SUMS_FAILED_TO_ALLOCATE_FILE_HASH1      | file hash object allocation failed                                         |
| 23   | CHECK_SUMS_FAILED_TO_ALLOCATE_WIDE_BUFFER2    | line buffer allocation for UTF-16 failed[2]                                |
| 24   | CHECK_SUMS_FAILED_TO_ALLOCATE_FILE_HASH2      | file hash object allocation failed[2]                                      |
| 25   | CHECK_SUMS_FAILED_TO_READ                     | failed to read from -c FILE                                                |
| 26   | CHECK_SUM_CHECKSUM_FAILED                     | checksum verification failed                                               |
| 27   | PRINT_HASH_FAILED_GET_FULL_PATH_NAME          | failed to determine absolute path of file                                  |
| 28   | PRINT_HASH_FAILED_STRING_LENGTH               | failed to determine string length for printing hashes                      |
| 29   | PRINT_HASH_FAILED_STRING_CAT1                 | failed to concatenate relative paths for printing hashes                   |
| 30   | PRINT_HASH_FAILED_STRING_CAT2                 | failed to concatenate relative paths for printing hashes                   |

[1] This should never occur. sha256sum.exe uses Microsoft's Cryptography API: Next Generation (CNG) with fixed values. If this happens the system is probably missing the CNG.

[2] There is a duplication for parsing the file when the end of file is not reached yet and for the remaining characters that are still in the read buffer.

## Design Decisions

I made several decisions regarding the APIs used in the code:

- **OpenSSL's EVP Functions**: My initial attempt involved using these, but I encountered issues with static linking.
- **Go Implementation**: Resulted in a larger file size than desired.
- **CNG and Windows API**: The current implementation uses these native APIs to minimize dependencies and file size.
