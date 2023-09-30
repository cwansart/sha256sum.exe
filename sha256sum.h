#pragma once

#include <errno.h>
#include <windows.h>
#include <stdio.h>

typedef enum errorCode
{
    SUCCESS = 0,

    // main
    MAIN_FAILED_TO_FIND_FILES,

    // parse_args
    PARSE_ARGS_MISSING_PARAMETER,
    PARSE_ARGS_MISSING_SHASUMS_FILE,
    PARSE_ARGS_ALLOCATE_ERROR,

    // calc_hash
    CALC_HASH_FAILED_TO_OPEN_FILE,
    CALC_HASH_FAILED_TO_OPEN_ALG_HANDLE,
    CALC_HASH_FAILED_TO_ALLOCATE_HASH_BUFFER_SIZE,
    CALC_HASH_FAILED_TO_ALLOCATE_HASH_OBJECT,
    CALC_HASH_FAILED_TO_CALC_HASH_LENGTH,
    CALC_HASH_FAILED_TO_ALLOCATE_HASH_BUFFER,
    CALC_HASH_FAILED_TO_CREATE_HASH,
    CALC_HASH_FAILED_TO_READ,
    CALC_HASH_FAILED_TO_HASH,
    CALC_HASH_FAILED_TO_FINISH_HASH,
    CALC_HASH_FAILED_TO_ALLOCATE_FILE_HASH,

    // parse_line
    PARSE_LINE_INVALID_HASH_TOKEN,
    PARSE_LINE_INVALID_HASH_LENGTH,
    PARSE_LINE_INAVLID_FILE,

    // check_sums
    CHECK_SUMS_FAILED_TO_OPEN_SUM_FILE,
    CHECK_SUMS_LINE_TOO_LONG,
    CHECK_SUMS_FAILED_TO_ALLOCATE_WIDE_BUFFER1,
    CHECK_SUMS_FAILED_TO_ALLOCATE_FILE_HASH1,
    CHECK_SUMS_FAILED_TO_ALLOCATE_WIDE_BUFFER2,
    CHECK_SUMS_FAILED_TO_ALLOCATE_FILE_HASH2,
    CHECK_SUMS_FAILED_TO_READ,
    CHECK_SUM_CHECKSUM_FAILED,
} ErrorCode;

typedef struct file_list
{
    LPWSTR file;
    struct file_list* next;
} FileList;

typedef struct prog_args
{
    FileList* files;
    LPWSTR sum_file;
    BOOL quiet;
    BOOL status;
    BOOL warn;
    BOOL show_version;
    BOOL text_mode;
} Args;

ErrorCode parse_args(__out Args*, __in int, __in LPWSTR[]);

ErrorCode print_hash(__in Args* args, __in LPWSTR);
ErrorCode check_sums(__in Args*);
