#include "sha256sum.h"

#define MAJOR_VERSION 2
#define MINOR_VERSION 0
#define PATCH_VERSION 0

int run(int argc, LPWSTR argv[])
{
    Args args = { 0 };
    ErrorCode parse_result = parse_args(&args, argc, argv);

    // error handling from argument parsing
    switch (parse_result)
    {
    case PARSE_ARGS_MISSING_PARAMETER:
    case PARSE_ARGS_MISSING_SHASUMS_FILE:
    case PARSE_ARGS_ALLOCATE_ERROR:
        return parse_result;
    }

    // show application version
    if (args.show_version)
    {
        wprintf(L"%ls version %d.%d.%d\n", argv[0], MAJOR_VERSION, MINOR_VERSION, PATCH_VERSION);
        return SUCCESS;
    }

    // since WinAPI only reads binary we don't support text mode
    if (args.text_mode)
    {
        wprintf(L"%ls only supports binary mode\n", argv[0]);
        return SUCCESS;
    }

    // run check on checksum file
    if (args.sum_file != NULL)
    {
        return check_sums(&args);
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
                wprintf(L"failed to find files for argument '%ls' with error %lu\n", current->file, GetLastError());
                return MAIN_FAILED_TO_FIND_FILES;
            }

            do
            {
                ErrorCode printHashStatus = print_hash(&args, findFileData.cFileName);
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
