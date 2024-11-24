#pragma once

#include <errno.h>
#include <windows.h>
#include <stdio.h>

typedef enum errorCode
{
    SUCCESS = 0,

    // main
    MAIN_FAILED_TO_FIND_FILES = 1,

    // parse_args
    PARSE_ARGS_MISSING_PARAMETER = 2,
    PARSE_ARGS_MISSING_SHASUMS_FILE = 3,
    PARSE_ARGS_ALLOCATE_ERROR = 4,

    // calc_hash
    CALC_HASH_FAILED_TO_OPEN_FILE = 5,
    CALC_HASH_FAILED_TO_OPEN_ALG_HANDLE = 6,
    CALC_HASH_FAILED_TO_ALLOCATE_HASH_BUFFER_SIZE = 7,
    CALC_HASH_FAILED_TO_ALLOCATE_HASH_OBJECT = 8,
    CALC_HASH_FAILED_TO_CALC_HASH_LENGTH = 9,
    CALC_HASH_FAILED_TO_ALLOCATE_HASH_BUFFER = 10,
    CALC_HASH_FAILED_TO_CREATE_HASH = 11,
    CALC_HASH_FAILED_TO_READ = 12,
    CALC_HASH_FAILED_TO_HASH = 13,
    CALC_HASH_FAILED_TO_FINISH_HASH = 14,
    CALC_HASH_FAILED_TO_ALLOCATE_FILE_HASH = 15,

    // parse_line
    PARSE_LINE_INVALID_HASH_TOKEN = 16,
    PARSE_LINE_INVALID_HASH_LENGTH = 17,
    PARSE_LINE_INAVLID_FILE = 18,

    // check_sums
    CHECK_SUMS_FAILED_UNSUPPORTED_UTF_16 = 34,
    CHECK_SUMS_FAILED_TO_OPEN_SUM_FILE = 19,
    CHECK_SUMS_LINE_TOO_LONG = 20,
    CHECK_SUMS_FAILED_TO_ALLOCATE_WIDE_BUFFER1 = 21,
    CHECK_SUMS_FAILED_TO_ALLOCATE_FILE_HASH1 = 22,
    CHECK_SUMS_FAILED_TO_ALLOCATE_WIDE_BUFFER2 = 23,
    CHECK_SUMS_FAILED_TO_ALLOCATE_FILE_HASH2 = 24,
    CHECK_SUMS_FAILED_TO_READ = 25,
    CHECK_SUM_CHECKSUM_FAILED = 26,

    // print_hash
    PRINT_HASH_FAILED_GET_FULL_PATH_NAME = 27,
    PRINT_HASH_FAILED_STRING_LENGTH = 28,
    PRINT_HASH_FAILED_STRING_CAT1 = 29,
    PRINT_HASH_FAILED_STRING_CAT2 = 30,
    PRINT_HASH_FAILED_STRING_CAT3 = 31,
    PRINT_HASH_FAILED_STRING_CAT4 = 32,
    PRINT_HASH_FAILED_STRING_CAT5 = 33,
} ErrorCode;

typedef struct file_list
{
    LPWSTR file;
    struct file_list* next;
} FileList;

typedef struct prog_args
{
    FileList* files;
    LPWSTR sumFile;
    BOOL quiet;
    BOOL status;
    BOOL warn;
    BOOL showVersion;
    BOOL textMode;
} Args;

// this is required for CppUnitTestFramework
#ifdef __cplusplus
extern "C" {
#endif

ErrorCode ParseArgs(__out Args*, __in int, __in LPWSTR[]);

ErrorCode CalcHash(__in Args*, __out LPWSTR*, __in LPWSTR);
ErrorCode PrintHash(__in Args*, __in LPWSTR, __in LPWSTR);
ErrorCode VerifyChecksums(__in Args*);

void WriteFileUTF8(__in HANDLE, __in LPWSTR);
WCHAR PathFindSeparator(__in LPWSTR, __in size_t);
BOOL PathRemoveFileName(__out_ecount(MAX_PATH) LPWSTR, __in LPWSTR);

#ifdef __cplusplus
}
#endif
