# sha256sum for Windows

Since `certutil` in CMD is not ideal for use in a Dockerfile and I prefer not to rely on random authors on the web, I've
created my own `sha256sum.exe` tool.

## Requirements

The *Makefile* is designed for use with MSVC. Specifically, I've developed it using VS 2017 version 14.16.27023.

## Building sha256sum.exe

1. Open the *x64 Native Tools Command Prompt for VS 2017*.
2. Navigate to the folder containing the Makefile.
3. Run the `nmake` command.

## How to Run

Either download the pre-compiled `sha256sum.exe` or build it yourself. To run the tool, execute it with a file
parameter. For example:

```bash
sha256sum.exe myText.txt
```

## Design Decisions

I made several decisions regarding the APIs used in the code. My initial attempt involved using OpenSSL's EVP functions,
but I encountered issues with static linking. Using a shared library resulted in an executable that was only about
120 KB in size, but it had a dependency on `libcrypto-3-x64.dll`, which is around 5-6 MB.

I also tried writing `sha256sum.exe` in Go, which resulted in a file size of around 1.2 MB. While this size is
acceptable, I wanted to minimize the file size for use in a nanoserver environment.

The current implementation uses the *Cryptography API: Next Generation* (CNG) and the Windows API for file reading. It
doesn't depend on any third-party libraries not already included in Windows, resulting in a very compact executable.
