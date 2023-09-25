#include "args.h"

#define TEST_RESULT(test_num, exp, act)                                                           \
  do                                                                                              \
  {                                                                                               \
    if ((act) == (exp))                                                                           \
    {                                                                                             \
      wprintf(L"TEST %ld: RESULT OK\n", (test_num));                                              \
    }                                                                                             \
    else                                                                                          \
    {                                                                                             \
      fwprintf(stderr, L"TEST %ld: RESULT expected=%ld, actual=%ld\n", (test_num), (exp), (act)); \
    }                                                                                             \
  } while (0)

#define TEST_SHA256_FILE(test_num, exp, act)                                                               \
  do                                                                                                       \
  {                                                                                                        \
    wchar_t *exp_str = (exp == NULL) ? L"NULL" : exp;                                                      \
    wchar_t *act_str = (act == NULL) ? L"NULL" : act;                                                      \
    if (wcscmp(exp_str, act_str) == 0)                                                                     \
    {                                                                                                      \
      wprintf(L"TEST %ld: SHA FILE OK\n", (test_num));                                                     \
    }                                                                                                      \
    else                                                                                                   \
    {                                                                                                      \
      fwprintf(stderr, L"TEST %ld SHA FILE expected=%ls, actual=%ls\n", (test_num), (exp_str), (act_str)); \
    }                                                                                                      \
  } while (0)

void wmain()
{
  int test_num = 1;

  { // TEST 1
    int argc = 1;
    wchar_t *argv[] = {L"prog"};
    wchar_t *shasums_file = NULL;
    errno_t act = parse_args(argc, argv, &shasums_file);
    errno_t exp = ARGS_MISSING_PARAMETER;
    TEST_RESULT(test_num, exp, act);
    TEST_SHA256_FILE(test_num++, NULL, shasums_file);
  }

  { // TEST 2
    int argc = 2;
    wchar_t *argv[] = {L"prog", L"-c"};
    wchar_t *shasums_file = NULL;
    errno_t act = parse_args(argc, argv, &shasums_file);
    errno_t exp = ARGS_MISSING_SHASUMS_FILE;
    TEST_RESULT(test_num, exp, act);
    TEST_SHA256_FILE(test_num++, NULL, shasums_file);
  }

  { // TEST 3
    int argc = 3;
    wchar_t *argv[] = {L"prog", L"-c", L"SHA256SUMS"};
    wchar_t *shasums_file = NULL;
    errno_t act = parse_args(argc, argv, &shasums_file);
    errno_t exp = OK;
    TEST_RESULT(test_num, exp, act);
    TEST_SHA256_FILE(test_num++, L"SHA256SUMS", shasums_file);
  }

  { // TEST 4
    int argc = 3;
    wchar_t *argv[] = {L"prog", L"file1", L"file2"};
    wchar_t *shasums_file = NULL;
    errno_t act = parse_args(argc, argv, &shasums_file);
    errno_t exp = OK;
    TEST_RESULT(test_num, exp, act);
    TEST_SHA256_FILE(test_num++, NULL, shasums_file);
  }
}
