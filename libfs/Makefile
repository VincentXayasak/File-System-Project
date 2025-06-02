# Target static library
lib := libfs.a

# Source files
src := fs.c disk.c

# Object files
obj := $(src:.c=.o)

# Compiler and flags
CC := gcc
CFLAGS := -Wall -Wextra -std=c99 -g

# Default rule
all: $(lib)

# Create the static library from object files
$(lib): $(obj)
	ar rcs $@ $^

# Pattern rule to compile .c to .o
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# Clean up build artifacts
clean:
	rm -f $(obj) $(lib)