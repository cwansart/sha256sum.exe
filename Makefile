# Compiler
CC = cl

# Flags for the compiler
CFLAGS = /W4 /MT /O2

# Include and lib directories for OpenSSL
OPENSSL_INCLUDE_DIR = include
OPENSSL_LIB_DIR = lib

# Name of the final executable
OUTFILE = sha256sum.exe

# Source files
SOURCES = main.c

# Object files (one per source file)
OBJECTS = $(SOURCES:.c=.obj)

# Default target
all: $(OUTFILE)

# Linking rule
$(OUTFILE): $(OBJECTS)
    $(CC) $(CFLAGS) /Fe$@ $(OBJECTS) /link /LIBPATH:"$(OPENSSL_LIB_DIR)"

# Compilation rule
.c.obj:
    $(CC) $(CFLAGS) /c $< /Fo$@ /I "$(OPENSSL_INCLUDE_DIR)"

# Clean rule
clean:
    del *.obj $(OUTFILE)

# Phony targets
.PHONY: all clean