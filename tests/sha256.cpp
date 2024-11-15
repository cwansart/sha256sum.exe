#include <CppUnitTest.h>
#include <sha256sum.h>
#include <direct.h>
#define GetCurrentDir _getcwd
#include <stdio.h>
#include <string>
#include <iostream>
#include <fstream>

using namespace Microsoft::VisualStudio::CppUnitTestFramework;

namespace sha256 {
TEST_CLASS(fCalcHash)
{
public:

    TEST_METHOD(TestValidHashCurrentPath)
    {
        Args args = { 0 };
        LPWSTR file = L"CalcHashTestFile.txt";

        LPWSTR hash = NULL;
        ErrorCode act = CalcHash(&args, &hash, file);
        ErrorCode exp = SUCCESS;

        Assert::AreEqual((int)exp, (int)act);
        Assert::AreEqual(L"5825c4a88eddd074eb3c12b23dedc0eb4d7d5f2356a61a4078a0bd3ccf69c7a1", hash);
    }

    TEST_METHOD(TestValidHashMissingFile)
    {
        Args args = { 0 };
        LPWSTR file = L"Missing.txt";

        LPWSTR hash = NULL;
        ErrorCode act = CalcHash(&args, &hash, file);
        ErrorCode exp = CALC_HASH_FAILED_TO_OPEN_FILE;

        Assert::AreEqual((int)exp, (int)act);
    }

    TEST_METHOD(TestValidHashAbsolutePath)
    {
        char cwd[FILENAME_MAX];
        if (!GetCurrentDir(cwd, sizeof(cwd)))
        {
            Assert::Fail(L"Can't get current path");
            return;
        }

        std::string fullPath = std::string(cwd) + "\\CalcHashTestFile.txt";
        std::wstring wideFullPath(fullPath.begin(), fullPath.end());

        Args args = { 0 };
        LPWSTR file = &wideFullPath[0];

        LPWSTR hash = NULL;
        ErrorCode act = CalcHash(&args, &hash, file);
        ErrorCode exp = SUCCESS;

        Assert::AreEqual((int)exp, (int)act);
        Assert::AreEqual(L"5825c4a88eddd074eb3c12b23dedc0eb4d7d5f2356a61a4078a0bd3ccf69c7a1", hash);
    }

    TEST_METHOD(TestValidHashRelativePath)
    {
        char tempCwd[FILENAME_MAX];
        if (!GetCurrentDir(tempCwd, sizeof(tempCwd)))
        {
            Assert::Fail(L"Can't get current path");
            return;
        }

        std::string cwd(tempCwd);

        size_t lastSeparator = cwd.find_last_of('\\');

        std::string lastPart;
        if (lastSeparator != std::string::npos) {
            lastPart = cwd.substr(lastSeparator + 1);
        }
        else {
            lastPart = cwd;
        }

        std::string fullPath = std::string(cwd) + "\\..\\" + lastPart + "\\CalcHashTestFile.txt";
        std::wstring wideFullPath(fullPath.begin(), fullPath.end());

        Args args = { 0 };
        LPWSTR file = &wideFullPath[0];

        LPWSTR hash = NULL;
        ErrorCode act = CalcHash(&args, &hash, file);
        ErrorCode exp = SUCCESS;

        Assert::AreEqual((int)exp, (int)act);
        Assert::AreEqual(L"5825c4a88eddd074eb3c12b23dedc0eb4d7d5f2356a61a4078a0bd3ccf69c7a1", hash);
    }
};

TEST_CLASS(fVerifyChecksums)
{
public:

    TEST_METHOD(TestSuccessCurrentPath)
    {
        Args args = { 0 };
        args.sumFile = L"ShasumSuccess.txt";

        LPWSTR hash = NULL;
        ErrorCode act = VerifyChecksums(&args);
        ErrorCode exp = SUCCESS;

        Assert::AreEqual((int)exp, (int)act);
    }

    TEST_METHOD(TestSuccessAbsolutePath)
    {
        char cwd[FILENAME_MAX];
        if (!GetCurrentDir(cwd, sizeof(cwd)))
        {
            Assert::Fail(L"Can't get current path");
            return;
        }

        std::string expectedChecksum = "5825c4a88eddd074eb3c12b23dedc0eb4d7d5f2356a61a4078a0bd3ccf69c7a1";
        std::string checksumFilename = "ShasumSuccessAbsolute.txt";
        std::ofstream checksumFile(checksumFilename);

        if (!checksumFile) {
            Assert::Fail(L"Count not create checksum file");
            return;
        }

        checksumFile << expectedChecksum << " *" << cwd << "\\CalcHashTestFile.txt" << std::endl;
        checksumFile.close();

        std::string fullPath = std::string(cwd) + "\\" + checksumFilename;

        std::wstring wideFullPath(fullPath.begin(), fullPath.end());
        Args args = { 0 };
        args.sumFile = &wideFullPath[0];

        LPWSTR hash = NULL;
        ErrorCode act = VerifyChecksums(&args);
        ErrorCode exp = SUCCESS;

        Assert::AreEqual((int)exp, (int)act);
    }

    TEST_METHOD(TestSuccessRelativePath)
    {
        char tempCwd[FILENAME_MAX];
        if (!GetCurrentDir(tempCwd, sizeof(tempCwd)))
        {
            Assert::Fail(L"Can't get current path");
            return;
        }

        std::string cwd(tempCwd);

        size_t lastSeparator = cwd.find_last_of('\\');

        std::string lastPart;
        if (lastSeparator != std::string::npos) {
            lastPart = cwd.substr(lastSeparator + 1);
        }
        else {
            lastPart = cwd;
        }

        std::string expectedChecksum = "5825c4a88eddd074eb3c12b23dedc0eb4d7d5f2356a61a4078a0bd3ccf69c7a1";
        std::string checksumFilename = "ShasumSuccessRelative.txt";
        std::ofstream checksumFile(checksumFilename);

        if (!checksumFile) {
            Assert::Fail(L"Count not create checksum file");
            return;
        }

        checksumFile << expectedChecksum << " *" << "..\\" << lastPart << "\\CalcHashTestFile.txt" << std::endl;
        checksumFile.close();

        std::string fullPath = std::string(cwd) + "\\" + checksumFilename;

        std::wstring wideFullPath(fullPath.begin(), fullPath.end());
        Args args = { 0 };
        args.sumFile = &wideFullPath[0];

        LPWSTR hash = NULL;
        ErrorCode act = VerifyChecksums(&args);
        ErrorCode exp = SUCCESS;

        Assert::AreEqual((int)exp, (int)act);
    }

    TEST_METHOD(TestFailure)
    {
        Args args = { 0 };
        args.sumFile = L"ShasumFailure.txt";

        LPWSTR hash = NULL;
        ErrorCode act = VerifyChecksums(&args);
        ErrorCode exp = CHECK_SUM_CHECKSUM_FAILED;

        Assert::AreEqual((int)exp, (int)act);
    }
};
}
