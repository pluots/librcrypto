# taken from https://www.throwtheswitch.org/build/make
# this builds the C source files but does not:
# - invoke cargo to build the Rust library (this must be done in advance)
# - run the tests (cargo does this)

ifeq ($(OS),Windows_NT)
  ifeq ($(shell uname -s),) # not in a bash-like shell
	cleanup = del /F /Q
	mkdir = mkdir
  else # in a bash-like shell, like msys
	cleanup = rm -f
	mkdir = mkdir -p
  endif
	target_extension = exe
	shared_extension = dll
else
  uname_s := $(shell uname -s)
  ifeq ($(uname_s),Linux)
   shared_extension = so
  endif
  ifeq ($(uname_s),Darwin)
    shared_extension = dylib
  endif
	cleanup = rm -f
	mkdir = mkdir -p
	target_extension = out
endif

.PHONY: clean
.PHONY: build

# OUT_DIR := build
outdir = $(OUT_DIR)
lib_name = rcrypto_sys

include_unity = c/unity/src/
include_rcrypto = ../../
include_framework = c/

dir_tests = ./
dir_build = $(outdir)/c-build/
dir_testout = $(outdir)/c-out/
dir_sharedlib = ../../target/debug/
path_sharedlib = $(dir_sharedlib)lib$(lib_name).$(shared_extension)

test_src_files = $(wildcard $(dir_tests)*.c)

compile = gcc -c -Wall -Werror --pedantic --std=c11
link = gcc
cflags = -I$(include_framework) -I$(include_unity) -I$(include_rcrypto) \
		 -I$(include_framework) -DTEST $(CFLAGS)

# add paths built by cargo
ldflags = -L$(dir_sharedlib) -l$(lib_name) $(LDFLAGS)

test_exe_files = $(patsubst $(dir_tests)%.c,$(dir_testout)test_%.$(target_extension),$(test_src_files))
build_paths = $(dir_build) $(dir_testout)

build: $(build_paths) $(test_exe_files)
	@echo generating C output to $(outdir)

# make all test executables
$(dir_testout)test_%.$(target_extension): $(dir_build)unity.o \
	$(dir_build)unity_framework.o  $(dir_build)test_%.o
	$(link) $(ldflags) -o $@ $^

# make all test object files
$(dir_build)test_%.o:: $(dir_tests)%.c
	$(compile) $(cflags) $< -o $@

$(dir_build)%.o:: $(include_unity)%.c $(include_unity)%.h
	$(compile) $(cflags) $< -o $@

$(dir_build)unity_framework.o: $(include_framework)unity_framework.c
	$(compile) $(cflags) $< -o $@

$(dir_build):
	$(mkdir) $(dir_build)

$(dir_testout):
	$(mkdir) $(dir_testout)

.PRECIOUS: $(pathb)test%.$(target_extension)
