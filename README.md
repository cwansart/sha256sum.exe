# sha256sum for Windows

Since certutil in cmd sucks and I don't trust any random author on the web I wrote my own sha256sum.exe tool.

## Requirements

The *Makefile* is developed for use with MSVC. I am using VS 2017 14.16.27023.

## Build sha256sum.exe

Start *x64 Native Tools Command Prompt for VS 2017*, navigate to the folder of the Makefile and run `nmake`.

## How to run

Download or compile the sha256sum.exe. Run the sha256sum.exe with a file parameter. For example:

```bash
sha256sum.exe myText.txt
```
