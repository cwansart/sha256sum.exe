#include <CppUnitTest.h>
#include <sha256sum.h>

using namespace Microsoft::VisualStudio::CppUnitTestFramework;

namespace args {
TEST_CLASS(fParseArgs)
{
public:

    TEST_METHOD(TestNoArgs)
    {
        LPWSTR argv[] = { L"prog" };
        int argc = 1;
        Args args = { 0 };

        ErrorCode act = ParseArgs(&args, argc, argv);
        ErrorCode exp = PARSE_ARGS_MISSING_PARAMETER;

        Assert::AreEqual((int)act, (int)exp);
    }

    TEST_METHOD(TestCheckWithoutSumFile)
    {
        LPWSTR argv[] = { L"prog", L"-c" };
        int argc = 2;
        Args args = { 0 };

        ErrorCode act = ParseArgs(&args, argc, argv);
        ErrorCode exp = PARSE_ARGS_MISSING_SHASUMS_FILE;

        Assert::AreEqual((int)act, (int)exp);
    }

    TEST_METHOD(TestCheckWithSumFile)
    {
        LPWSTR argv[] = { L"prog", L"-c", L"SHA256SUMS" };
        int argc = 3;
        Args args = { 0 };

        ErrorCode act = ParseArgs(&args, argc, argv);
        ErrorCode exp = SUCCESS;

        Assert::AreEqual((int)act, (int)exp);
        Assert::AreEqual(args.sumFile, L"SHA256SUMS");
    }

    TEST_METHOD(TestFiles)
    {
        LPWSTR argv[] = { L"prog", L"file1", L"file2" };
        int argc = 3;
        Args args = { 0 };

        ErrorCode act = ParseArgs(&args, argc, argv);
        ErrorCode exp = SUCCESS;

        Assert::AreEqual((int)act, (int)exp);
        Assert::AreEqual(args.files->file, L"file1");
        Assert::AreEqual(args.files->next->file, L"file2");
    }

    TEST_METHOD(TestVersion)
    {
        LPWSTR argv[] = { L"prog", L"-v" };
        int argc = 2;
        Args args = { 0 };

        ErrorCode act = ParseArgs(&args, argc, argv);
        ErrorCode exp = SUCCESS;

        Assert::AreEqual((int)act, (int)exp);
        Assert::AreEqual(args.showVersion, TRUE);
    }

    TEST_METHOD(TestTextMode)
    {
        LPWSTR argv[] = { L"prog", L"-t" };
        int argc = 2;
        Args args = { 0 };

        ErrorCode act = ParseArgs(&args, argc, argv);
        ErrorCode exp = SUCCESS;

        Assert::AreEqual((int)act, (int)exp);
        Assert::AreEqual(args.textMode, TRUE);
    }

    TEST_METHOD(TestStatus)
    {
        LPWSTR argv[] = { L"prog", L"-s" };
        int argc = 2;
        Args args = { 0 };

        ErrorCode act = ParseArgs(&args, argc, argv);
        ErrorCode exp = SUCCESS;

        Assert::AreEqual((int)act, (int)exp);
        Assert::AreEqual(args.status, TRUE);
    }

    TEST_METHOD(TestWarn)
    {
        LPWSTR argv[] = { L"prog", L"-w" };
        int argc = 2;
        Args args = { 0 };

        ErrorCode act = ParseArgs(&args, argc, argv);
        ErrorCode exp = SUCCESS;

        Assert::AreEqual((int)act, (int)exp);
        Assert::AreEqual(args.warn, TRUE);
    }
};
}
