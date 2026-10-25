CC ?= cc
CFLAGS ?= -O2 -std=c11 -Wall -Wextra -Wpedantic -Werror
CPPFLAGS += -D_POSIX_C_SOURCE=200809L -D_XOPEN_SOURCE=700 -D_DARWIN_C_SOURCE
SOURCES := $(wildcard src/*.c)

.PHONY: all test clean
all: build/leanwin
ifeq ($(shell uname -s),Darwin)
all: build/liblwgui.dylib
build/liblwgui.dylib: src/gui.m
	mkdir -p build
	$(CC) -O2 -Wall -Wextra -Werror -fobjc-arc -dynamiclib -framework AppKit $< -o $@
endif
build/leanwin: $(SOURCES) $(wildcard src/*.h)
	mkdir -p build
	$(CC) $(CPPFLAGS) $(CFLAGS) $(SOURCES) -o $@
test: all
	python3 -m unittest discover -s tests -v
clean:
	rm -rf build
