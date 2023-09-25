#pragma once
#include <wchar.h>

#define OK 0
#define ARGS_MISSING_PARAMETER 1
#define ARGS_MISSING_SHASUMS_FILE 2

errno_t parse_args(int argc, wchar_t *argv[], wchar_t **out_shasums_file);
void usage(wchar_t *prog, wchar_t *message);
