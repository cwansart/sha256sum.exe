#include "pch.h"
#include "CppUnitTest.h"
#include <sha256sum.h>

using namespace Microsoft::VisualStudio::CppUnitTestFramework;

namespace sha256 {
TEST_CLASS(fCalcHash)
{
public:

    TEST_METHOD(TestValidHash)
    {
        Args args = { 0 };
        LPWSTR file = L"CalcHashTestFile.txt";

        LPWSTR hash = NULL;
        ErrorCode act = CalcHash(&args, &hash, file);
        ErrorCode exp = SUCCESS;

        Assert::AreEqual((int)act, (int)exp);
        Assert::AreEqual(L"5825c4a88eddd074eb3c12b23dedc0eb4d7d5f2356a61a4078a0bd3ccf69c7a1", hash);
    }
};

TEST_CLASS(fVerifyChecksums)
{
public:

    TEST_METHOD(TestSuccess)
    {
        Args args = { 0 };
        args.sumFile = L"ShasumSuccess.txt";

        LPWSTR hash = NULL;
        ErrorCode act = VerifyChecksums(&args);
        ErrorCode exp = SUCCESS;

        Assert::AreEqual((int)act, (int)exp);
    }

    TEST_METHOD(TestFailure)
    {
        Args args = { 0 };
        args.sumFile = L"ShasumFailure.txt";

        LPWSTR hash = NULL;
        ErrorCode act = VerifyChecksums(&args);
        ErrorCode exp = CHECK_SUM_CHECKSUM_FAILED;

        Assert::AreEqual((int)act, (int)exp);
    }
};
}
