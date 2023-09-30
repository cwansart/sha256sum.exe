#include "sha256sum.h"

#ifdef _UNITTESTS

#define TEST_ARGS_RESULT(test_num, exp, act)                                                  \
  do                                                                                          \
  {                                                                                           \
    if ((act) != (exp))                                                                       \
    {                                                                                         \
      has_failures = TRUE;                                                                    \
      has_local_failures = TRUE;                                                              \
      wprintf(L"ARGS TEST %ld: RESULT expected=%ld, actual=%ld\n", (test_num), (exp), (act)); \
    }                                                                                         \
  } while (0)

#define TEST_ARGS_SHA256_FILE(test_num, exp, act)                                                      \
  do                                                                                                   \
  {                                                                                                    \
    wchar_t *exp_str = (exp == NULL) ? L"NULL" : exp;                                                  \
    wchar_t *act_str = (act == NULL) ? L"NULL" : act;                                                  \
    if (wcscmp(exp_str, act_str) != 0)                                                                 \
    {                                                                                                  \
      has_failures = TRUE;                                                                             \
      has_local_failures = TRUE;                                                                       \
      wprintf(L"ARGS TEST %ld SHA FILE: RESULT expected=%ls, actual=%ls\n", (test_num), (exp_str), (act_str)); \
    }                                                                                                  \
  } while (0)

#define TEST_ARGS_FILE(test_num, exp, act)                                                         \
  do                                                                                               \
  {                                                                                                \
    wchar_t *exp_str = (exp == NULL) ? L"NULL" : exp;                                              \
    wchar_t *act_str = (act == NULL) ? L"NULL" : act;                                              \
    if (wcscmp(exp_str, act_str) != 0)                                                             \
    {                                                                                              \
      has_failures = TRUE;                                                                         \
      has_local_failures = TRUE;                                                                   \
      wprintf(L"ARGS TEST %ld FILE: RESULT expected=%ls, actual=%ls\n", (test_num), (exp_str), (act_str)); \
    }                                                                                              \
  } while (0)

#define TEST_FLAG(test_num, what, exp, act)                                                             \
  do                                                                                                    \
  {                                                                                                     \
    if (exp != act)                                                                                     \
    {                                                                                                   \
      has_failures = TRUE;                                                                              \
      has_local_failures = TRUE;                                                                        \
      wprintf(L"ARGS TEST %ld %ls FLAG: RESULT expected=%ld, actual=%ld\n", (test_num), (what), (exp), (act));  \
    }                                                                                                   \
  } while (0)

#define INIT_TEST (test_num++, has_local_failures = FALSE)

void print_success(LPWSTR type, int test_num, BOOL has_local_failures)
{
    if (has_local_failures == FALSE)
    {
        wprintf(L"%ls TEST %ld: RESULT OK\n", type, test_num);
    }
    printf("\n");
}

int count_args(wchar_t* argv[])
{
    int count = 0;
    while (argv[count] != NULL)
    {
        count++;
    }
    return count;
}

BOOL test_args()
{
    BOOL has_failures = FALSE;
    BOOL has_local_failures = FALSE;
    wprintf(L"TEST ARGS\n\n");
    int test_num = 0;

    { // TEST 1: test if no arguments where passed
        INIT_TEST;
        wchar_t* argv[] = { L"prog" };
        int argc = 1;
        Args args = { 0 };
        ErrorCode act = parse_args(&args, argc, argv);
        ErrorCode exp = PARSE_ARGS_MISSING_PARAMETER;
        TEST_ARGS_RESULT(test_num, exp, act);
        TEST_ARGS_SHA256_FILE(test_num++, NULL, args.sum_file);
        print_success(L"ARGS", test_num, has_local_failures);
    }

    { // TEST 2: test if -c was passed without a FILE
        INIT_TEST;
        wchar_t* argv[] = { L"prog", L"-c" };
        int argc = 2;
        Args args = { 0 };
        ErrorCode act = parse_args(&args, argc, argv);
        ErrorCode exp = PARSE_ARGS_MISSING_SHASUMS_FILE;
        TEST_ARGS_RESULT(test_num, exp, act);
        print_success(L"ARGS", test_num, has_local_failures);
    }

    { // TEST 3: test valid -c FILE arguments
        INIT_TEST;
        wchar_t* argv[] = { L"prog", L"-c", L"SHA256SUMS" };
        int argc = 3;
        Args args = { 0 };
        ErrorCode act = parse_args(&args, argc, argv);
        ErrorCode exp = SUCCESS;
        TEST_ARGS_RESULT(test_num, exp, act);
        TEST_ARGS_SHA256_FILE(test_num, L"SHA256SUMS", args.sum_file);
        print_success(L"ARGS", test_num, has_local_failures);

    }

    { // TEST 4: test just file arguments
        INIT_TEST;
        wchar_t* argv[] = { L"prog", L"file1", L"file2" };
        int argc = 3;
        Args args = { 0 };
        ErrorCode act = parse_args(&args, argc, argv);
        ErrorCode exp = SUCCESS;
        TEST_ARGS_RESULT(test_num, exp, act);
        TEST_ARGS_FILE(test_num, L"file1", args.files->file);
        TEST_ARGS_FILE(test_num, L"file2", args.files->next->file);
        print_success(L"ARGS", test_num, has_local_failures);
    }

    { // TEST 5: test version parameter
        INIT_TEST;
        wchar_t* argv[] = { L"prog", L"-v" };
        int argc = 2;
        Args args = { 0 };
        ErrorCode act = parse_args(&args, argc, argv);
        ErrorCode exp = SUCCESS;
        TEST_ARGS_RESULT(test_num, exp, act);
        TEST_FLAG(test_num, L"SHOW VERSION", TRUE, args.show_version);
        print_success(L"ARGS", test_num, has_local_failures);
    }

    { // TEST 6: test text mode parameter
        INIT_TEST;
        wchar_t* argv[] = { L"prog", L"-t" };
        int argc = 2;
        Args args = { 0 };
        ErrorCode act = parse_args(&args, argc, argv);
        ErrorCode exp = SUCCESS;
        TEST_ARGS_RESULT(test_num, exp, act);
        TEST_FLAG(test_num, L"TEXT MODE", TRUE, args.text_mode);
        print_success(L"ARGS", test_num, has_local_failures);
    }

    { // TEST 7: test text mode parameter
        INIT_TEST;
        wchar_t* argv[] = { L"prog", L"-q" };
        int argc = 2;
        Args args = { 0 };
        ErrorCode act = parse_args(&args, argc, argv);
        ErrorCode exp = SUCCESS;
        TEST_ARGS_RESULT(test_num, exp, act);
        TEST_FLAG(test_num, L"QUIET", TRUE, args.quiet);
        print_success(L"ARGS", test_num, has_local_failures);
    }

    { // TEST 8: test status parameter
        INIT_TEST;
        wchar_t* argv[] = { L"prog", L"-s" };
        int argc = 2;
        Args args = { 0 };
        ErrorCode act = parse_args(&args, argc, argv);
        ErrorCode exp = SUCCESS;
        TEST_ARGS_RESULT(test_num, exp, act);
        TEST_FLAG(test_num, L"STATUS", TRUE, args.status);
        print_success(L"ARGS", test_num, has_local_failures);
    }

    { // TEST 9: test warn parameter
        INIT_TEST;
        wchar_t* argv[] = { L"prog", L"-w" };
        int argc = 2;
        Args args = { 0 };
        ErrorCode act = parse_args(&args, argc, argv);
        ErrorCode exp = SUCCESS;
        TEST_ARGS_RESULT(test_num, exp, act);
        TEST_FLAG(test_num, L"WARN", TRUE, args.warn);
        print_success(L"ARGS", test_num, has_local_failures);
    }

    return has_failures;
}

BOOL run_tests()
{
    BOOL has_failures = test_args();

    if (has_failures == TRUE)
    {
        printf("TESTS FAILED\n");
    }
    else
    {
        printf("TESTS SUCCEEDED\n");
    }

    return has_failures;
}
#endif
