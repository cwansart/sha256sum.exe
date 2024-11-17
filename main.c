#include "sha256sum.h"

#define MAJOR_VERSION 2
#define MINOR_VERSION 0
#define PATCH_VERSION 3

int run(int argc, LPWSTR argv[])
{
    Args args = { 0 };
    ErrorCode parse_result = ParseArgs(&args, argc, argv);

    // error handling from argument parsing
    switch (parse_result)
    {
    case PARSE_ARGS_MISSING_PARAMETER:
    case PARSE_ARGS_MISSING_SHASUMS_FILE:
    case PARSE_ARGS_ALLOCATE_ERROR:
        return parse_result;
    }

    // show application version
    if (args.showVersion)
    {
        wprintf(L"%ls version %d.%d.%d\n", argv[0], MAJOR_VERSION, MINOR_VERSION, PATCH_VERSION);
        return SUCCESS;
    }

    // since WinAPI only reads binary we don't support text mode
    if (args.textMode)
    {
        wprintf(L"%ls only supports binary mode\n", argv[0]);
        return SUCCESS;
    }

    // run check on checksum file
    if (args.sumFile != NULL)
    {
        return VerifyChecksums(&args);
    }

    // handle all FILE parameters
    if (args.files != NULL)
    {
        FileList* current = args.files;
        while (current != NULL)
        {
            WIN32_FIND_DATA findFileData;
            HANDLE hFind = FindFirstFile(current->file, &findFileData);

            if (hFind == INVALID_HANDLE_VALUE)
            {
                wchar_t msg[MAX_PATH + 100];
                wsprintfW(msg, L"failed to find files for argument '%ls' with error %lu\n", current->file, GetLastError());
                WriteConsoleW(GetStdHandle(STD_OUTPUT_HANDLE), msg, lstrlenW(msg), NULL, NULL);
                return MAIN_FAILED_TO_FIND_FILES;
            }

            do
            {
                ErrorCode printHashStatus = PrintHash(&args, current->file, findFileData.cFileName);
                if (printHashStatus != SUCCESS)
                {
                    FindClose(hFind);
                    return printHashStatus;
                }
            } while (FindNextFile(hFind, &findFileData) != 0);

            FindClose(hFind);

            current = current->next;
        }
        return SUCCESS;
    }

    return SUCCESS;
}

int wmain(int argc, LPWSTR argv[])
{
    return run(argc, argv);
}
