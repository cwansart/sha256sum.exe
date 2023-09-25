#include "args.h"
#include "sha256.h"

int wmain(int argc, wchar_t *argv[])
{
  wchar_t *shasums_file = NULL;

  errno_t parse_result = parse_args(argc, argv, &shasums_file);
  if (parse_result != OK)
  {
    return 1;
  }

  // just print checksum
  if (shasums_file == NULL)
  {
    wchar_t *file_hash = calc_hash(argv[1]);
    if (file_hash != NULL)
    {
      wprintf(L"%ls %ls\n", file_hash, argv[1]);
    }
  }
  // check SHASUMS
  else
  {
    wprintf(L"to be implemented");
  }
}
