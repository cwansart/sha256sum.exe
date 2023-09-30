#include "sha256sum.h"

void usage(__in LPWSTR prog, __in_opt LPWSTR message)
{
#ifndef _UNITTESTS
    if (NULL != message)
    {
        wprintf(L"%ls\n", message);
    }
    wprintf(L"Usage: %ls [-c sha256sums_file] [file...]\n", prog);
#endif
}

ErrorCode parse_args(__out Args* args, __in int argc, __in LPWSTR argv[])
{
    ErrorCode status = SUCCESS;
    FileList* current = NULL;

    // default values
    args->files = NULL;
    args->sum_file = NULL;
    args->quiet = FALSE;
    args->status = FALSE;
    args->warn = FALSE;
    args->show_version = FALSE;
    args->text_mode = FALSE;

    // check if there are any argments given
    if (argc < 2)
    {
        usage(argv[0], L"too few arguments");
        status = PARSE_ARGS_MISSING_PARAMETER;
        goto Cleanup;
    }

    for (int i = 1; i < argc; ++i)
    {
        // -v, --version
        if (wcscmp(argv[i], L"-v") == 0 || wcscmp(argv[i], L"--version") == 0)
        {
            args->show_version = TRUE;
            goto Cleanup;
        }

        // -t, --text
        if (wcscmp(argv[i], L"-t") == 0 || wcscmp(argv[i], L"--text") == 0)
        {
            args->text_mode = TRUE;
            goto Cleanup;
        }

        // -b, --binary
        if (wcscmp(argv[i], L"-b") == 0 || wcscmp(argv[i], L"--binary") == 0)
        {
            // do nothing, since this only works with binary
            continue;
        }
        
        // -q, --quiet
        if (wcscmp(argv[i], L"-q") == 0 || wcscmp(argv[i], L"--quiet") == 0)
        {
            args->quiet = TRUE;
            continue;
        }
        
        // -s, --status
        if (wcscmp(argv[i], L"-s") == 0 || wcscmp(argv[i], L"--status") == 0)
        {
            args->status = TRUE;
            continue;
        }
        
        // -w, --warn
        if (wcscmp(argv[i], L"-w") == 0 || wcscmp(argv[i], L"--warn") == 0)
        {
            args->warn = TRUE;
            continue;
        }
        
        // -c, --check <file>
        // checks for -c or --check and checks the following argument
        // fails when there is no other argument after -c
        if (wcscmp(argv[i], L"-c") == 0 || wcscmp(argv[i], L"--check") == 0)
        {
            // check if there is another argument after -c
            if (i + 1 < argc)
            {
                args->sum_file = argv[i + 1];
                ++i; // skip next argument since we used it here
                continue;
            }
            else
            {
                usage(argv[0], L"missing SHA256SUMS file");
                status = PARSE_ARGS_MISSING_SHASUMS_FILE;
                goto Cleanup;
            }
        }
        // if there are no argument handling left, we assume the rest are files
        else
        {
            FileList* newFile = malloc(sizeof(FileList));
            if (newFile == NULL)
            {
                wprintf(L"allocation for new file list item failed\n");
                status = PARSE_ARGS_ALLOCATE_ERROR;
                goto Cleanup;
            }
            newFile->file = argv[i];
            newFile->next = NULL;

            if (args->files == NULL)
            {
                args->files = newFile;
                current = args->files;
            }
            else
            {
                current->next = newFile;
                current = newFile;
            }
        }
    }

Cleanup:
    return status;
}
