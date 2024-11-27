# Compiler and flags
CC = gcc
CFLAGS = -Wall -g

# Source files
SRC = main.c aes_crypto.c aes_functions.c aes_utils.c gf256.c

# Header files
INCLUDE = aes_crypto.h aes_functions.h gf256.h

# Output binary
OUT = aes_encrypt

# Default target to compile the project
all: $(OUT)

# Rule to create the output binary
$(OUT): $(SRC)
	$(CC) $(CFLAGS) -o $(OUT) $(SRC)

# Rule to clean the generated files
clean:
	rm -f $(OUT)

# Rule to recompile everything
rebuild: clean all
