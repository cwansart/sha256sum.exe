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

TEST_CLASS(fPathRemoveFileName)
{
public:

    TEST_METHOD(TestFileWithoutPath)
    {
        WCHAR path[MAX_PATH];
        LPWSTR filePath = L"CalcHashTestFile.txt";

        BOOL ret = PathRemoveFileName(path, filePath);

        Assert::AreEqual(FALSE, ret);
        Assert::AreEqual(L"", path);
    }

    TEST_METHOD(TestAbsolutePathWithBackslashes)
    {
        WCHAR path[MAX_PATH];
        LPWSTR filePath = L"C:\\Program Files\\Sha256sum\\CalcHashTestFile.txt";

        BOOL ret = PathRemoveFileName(path, filePath);

        Assert::AreEqual(TRUE, ret);
        Assert::AreEqual(L"C:\\Program Files\\Sha256sum", path);
    }

    TEST_METHOD(TestAbsolutePathWithSlashes)
    {
        WCHAR path[MAX_PATH];
        LPWSTR filePath = L"C:/Program Files/Sha256sum/CalcHashTestFile.txt";

        BOOL ret = PathRemoveFileName(path, filePath);

        Assert::AreEqual(TRUE, ret);
        Assert::AreEqual(L"C:/Program Files/Sha256sum", path);
    }

    TEST_METHOD(TestAbsolutePathWithBackslashAndParentDir)
    {
        WCHAR path[MAX_PATH];
        LPWSTR filePath = L"C:\\Program Files\\Sha256sum\\..\\CalcHashTestFile.txt";

        BOOL ret = PathRemoveFileName(path, filePath);

        Assert::AreEqual(TRUE, ret);
        Assert::AreEqual(L"C:\\Program Files\\Sha256sum\\..", path);
    }

    TEST_METHOD(TestAbsolutePathWithSlashAndParentDir)
    {
        WCHAR path[MAX_PATH];
        LPWSTR filePath = L"C:/Program Files/Sha256sum/../CalcHashTestFile.txt";

        BOOL ret = PathRemoveFileName(path, filePath);

        Assert::AreEqual(TRUE, ret);
        Assert::AreEqual(L"C:/Program Files/Sha256sum/..", path);
    }

    TEST_METHOD(TestRelativePathWithBackslash)
    {
        WCHAR path[MAX_PATH];
        LPWSTR filePath = L".\\CalcHashTestFile.txt";

        BOOL ret = PathRemoveFileName(path, filePath);

        Assert::AreEqual(TRUE, ret);
        Assert::AreEqual(L".", path);
    }

    TEST_METHOD(TestRelativePathWithSlash)
    {
        WCHAR path[MAX_PATH];
        LPWSTR filePath = L"./CalcHashTestFile.txt";

        BOOL ret = PathRemoveFileName(path, filePath);

        Assert::AreEqual(TRUE, ret);
        Assert::AreEqual(L".", path);
    }

    TEST_METHOD(TestRelativePathWithBackslashAndParentDir)
    {
        WCHAR path[MAX_PATH];
        LPWSTR filePath = L".\\..\\CalcHashTestFile.txt";

        BOOL ret = PathRemoveFileName(path, filePath);

        Assert::AreEqual(TRUE, ret);
        Assert::AreEqual(L".\\..", path);
    }

    TEST_METHOD(TestRelativePathWithSlashAndParentDir)
    {
        WCHAR path[MAX_PATH];
        LPWSTR filePath = L"./../CalcHashTestFile.txt";

        BOOL ret = PathRemoveFileName(path, filePath);

        Assert::AreEqual(TRUE, ret);
        Assert::AreEqual(L"./..", path);
    }
};

TEST_CLASS(fPathFindSeparator)
{
public:

    TEST_METHOD(TestPathSeparator1)
    {
        WCHAR sep = PathFindSeparator(L"C:/example/path/to/file.txt", 28);
        Assert::AreEqual(L'/', sep);
    }

    TEST_METHOD(TestPathSeparator2)
    {
        WCHAR sep = PathFindSeparator(L"C:\\example\\path\\to\\file.txt", 29);
        Assert::AreEqual(L'\\', sep);
    }

    TEST_METHOD(TestPathSeparator3)
    {
        WCHAR sep = PathFindSeparator(L"file.txt", 8);
        Assert::AreEqual(L'\\', sep);
    }

    TEST_METHOD(TestPathSeparator4)
    {
        WCHAR sep = PathFindSeparator(L"C:/example\\path/to/file.txt", 29);
        Assert::AreEqual(L'/', sep); 
    }

    TEST_METHOD(TestPathSeparator5)
    {
        WCHAR sep = PathFindSeparator(L"", 0);
        Assert::AreEqual(L'\\', sep);
    }

    TEST_METHOD(TestPathSeparator6)
    {
        WCHAR sep = PathFindSeparator(L"file.txt", 0);
        Assert::AreEqual(L'\\', sep);
    }

    TEST_METHOD(TestPathSeparator7)
    {
        WCHAR sep = PathFindSeparator(L"/", 1);
        Assert::AreEqual(L'/', sep);
    }

    TEST_METHOD(TestPathSeparator8)
    {
        WCHAR sep = PathFindSeparator(L"\\", 1);
        Assert::AreEqual(L'\\', sep);
    }

    TEST_METHOD(TestPathSeparator9)
    {
        WCHAR sep = PathFindSeparator(L"C:/path/to/", 12);
        Assert::AreEqual(L'/', sep);
    }

    TEST_METHOD(TestPathSeparator10)
    {
        WCHAR sep = PathFindSeparator(L"examplefile.txt", 14);
        Assert::AreEqual(L'\\', sep); 
    }

    TEST_METHOD(TestPathSeparator11)
    {
        WCHAR sep = PathFindSeparator(L"C:?<>|file.txt", 14);
        Assert::AreEqual(L'\\', sep);
    }

    TEST_METHOD(TestPathSeparator12)
    {
        WCHAR sep = PathFindSeparator(L"//////", 6);
        Assert::AreEqual(L'/', sep);
    }
};
}
