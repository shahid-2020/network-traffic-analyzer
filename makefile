# ----------------------------------------
# Compiler & flags
# ----------------------------------------
CC = gcc
CFLAGS = -Wall -Wextra -g
LIBS = -lpcap

# ----------------------------------------
# Source & target paths
# ----------------------------------------
SRC = ./src/traffic_analyzer.c
BUILD_DIR = ./exec
TARGET = $(BUILD_DIR)/traffic_analyzer

# ----------------------------------------
# Default target: build avoids conflict with folder name
# ----------------------------------------
all: build

# ----------------------------------------
# safe_build = create build dir + compile
# ----------------------------------------
build: $(BUILD_DIR) $(TARGET)

# ----------------------------------------
# Create build dir if missing
# ----------------------------------------
$(BUILD_DIR):
	@echo "Creating build directory: $(BUILD_DIR)"
	mkdir -p $(BUILD_DIR)

# ----------------------------------------
# Actual binary build (ensure build dir exists)
# ----------------------------------------
$(TARGET): $(SRC) $(BUILD_DIR)
	@echo "Compiling $(SRC) -> $(TARGET)"
	$(CC) $(CFLAGS) -o $(TARGET) $(SRC) $(LIBS)
	@echo "Build complete!"

# ----------------------------------------
# Clean build output
# ----------------------------------------
clean:
	@echo "Cleaning up..."
	rm -rf $(BUILD_DIR)
	@echo "Clean complete."

# ----------------------------------------
# Run the program
# ----------------------------------------
run: build
	@echo "Running $(TARGET) on interface en0..."
	sudo $(TARGET) en0

# ----------------------------------------
# Help
# ----------------------------------------
help:
	@echo "Usage:"
	@echo "  make build       - Build the program"
	@echo "  make run         - Build and run on en0"
	@echo "  make clean       - Remove build folder"
	@echo "  make help        - Show this message"

.PHONY: all safe_build clean run help
