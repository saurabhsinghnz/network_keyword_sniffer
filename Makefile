SHELL = /bin/sh

CC = g++
CFLAGS = -std=c++11 -c
LIBS = -lpcap -lz

INCLUDE = -I./include
BUILD = ./build
BIN = ./bin
TARGET = AlertProgram

OBJ_DIR = $(BUILD)
SRC_DIR = ./src

SOURCES = $(wildcard $(SRC_DIR)/*.cpp)
OBJECTS = $(patsubst $(SRC_DIR)/%.cpp, $(OBJ_DIR)/%.o, $(SOURCES))

all: build $(BIN)/$(TARGET)
	@echo "\nBinary created at $(BIN)/$(TARGET)"

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.cpp
	$(CC) $(CFLAGS) $(INCLUDE) $< -o $@

build:
	mkdir -p $(BUILD)

$(BIN)/$(TARGET): $(OBJECTS)
	$(CC) $(INCLUDE) $(BUILD)/*.o $(LIBS) -o $(BIN)/$(TARGET)

clean:
	rm -rf $(BUILD)/*.o $(BIN)/$(TARGET)
