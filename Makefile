# Compiler
CC = cl

# Flags for the compiler
CFLAGS = /W4 /MD /O2

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
    $(CC) $(CFLAGS) /Fe$@ $(OBJECTS) /link

# Compilation rule
.c.obj:
    $(CC) $(CFLAGS) /c $< /Fo$@

# Clean rule
clean:
    del *.obj $(OUTFILE)

# Phony targets
.PHONY: all clean
