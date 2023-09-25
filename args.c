#include "args.h"

errno_t parse_args(int argc, wchar_t *argv[], wchar_t **out_shasums_file)
{
  if (argc < 2)
  {
    usage(argv[0], L"missing parameter");
    return ARGS_MISSING_PARAMETER;
  }

  for (int i = 0; i < argc; ++i)
  {
    if (wcscmp(argv[i], L"-c") == 0)
    {
      // check if there is another argument after -c
      if (i + 1 < argc)
      {
        *out_shasums_file = argv[i + 1];
        ++i; // skip next argument since we used it here
      }
      else
      {
        usage(argv[0], L"");
        return ARGS_MISSING_SHASUMS_FILE;
      }
    }
  }

  return OK;
}

void usage(wchar_t *prog, wchar_t *message)
{
  if (NULL != message)
  {
    fwprintf(stderr, L"%ls\n", message);
  }

  wprintf(L"Usage: %ls [-c sha256sums_file] [file...]\n", prog);
}