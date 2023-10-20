# taken from https://www.throwtheswitch.org/build/make

ifeq ($(OS),Windows_NT)
  ifeq ($(shell uname -s),) # not in a bash-like shell
	CLEANUP = del /F /Q
	MKDIR = mkdir
  else # in a bash-like shell, like msys
	CLEANUP = rm -f
	MKDIR = mkdir -p
  endif
	TARGET_EXTENSION=exe
else
	CLEANUP = rm -f
	MKDIR = mkdir -p
	TARGET_EXTENSION=out
endif

.PHONY: clean
.PHONY: test

PATHUNITY = unity/src/
PATHTESTS = test/
PATHBUILD = build/
PATHBIN   = build/bin/
PATHRCHDR = "../"
PATHDYLIB = "../target/debug/librcrypto_sys.so"

SRCTESTS = $(wildcard $(PATHTESTS)*.c)

COMPILE=gcc -c -Wall -Werror --pedantic --std=c11
LINK=gcc
CFLAGS=-I. -I$(PATHUNITY) -I$(PATHRCHDR) -DTEST
# add paths built by cargo
LDFLAGS=-L$(PATHDEBUG) -lrcrypto_sys

RESULTS = $(patsubst $(PATHTESTS)%.c,$(PATHBUILD)test_%.txt,$(SRCTESTS) )
BUILD_PATHS = $(PATHBUILD) $(PATHBIN)

PASSED = `grep -s PASS $(PATHBUILD)*.txt`
FAIL = `grep -s FAIL $(PATHBUILD)*.txt`
IGNORE = `grep -s IGNORE $(PATHBUILD)*.txt`

test: $(BUILD_PATHS) $(RESULTS)
	@echo "-----------------------\nIGNORES:\n-----------------------"
	@echo "$(IGNORE)"
	@echo "-----------------------\nFAILURES:\n-----------------------"
	@echo "$(FAIL)"
	@echo "-----------------------\nPASSED:\n-----------------------"
	@echo "$(PASSED)"
	@echo "\nDONE"

# execute the result and write it to the text file
$(PATHBUILD)%.txt: $(PATHBIN)%.$(TARGET_EXTENSION)
	-./$< > $@ 2>&1

# make all test executables
$(PATHBIN)test%.$(TARGET_EXTENSION): $(PATHBIN)test%.o $(PATHDYLIB) \
	$(PATHBIN)unity.o $(PATHBIN)unity_framework.o
	$(LINK) $(LDFLAGS) -o $@ $^

# make all test object files
$(PATHBIN)test_%.o:: $(PATHTESTS)%.c
	$(COMPILE) $(CFLAGS) $< -o $@

$(PATHBIN)%.o:: $(PATHUNITY)%.c $(PATHUNITY)%.h
	$(COMPILE) $(CFLAGS) $< -o $@

$(PATHBIN)unity_framework.o: unity_framework.c
	$(COMPILE) $(CFLAGS) $< -o $@

$(PATHBUILD):
	$(MKDIR) $(PATHBUILD)

$(PATHBIN):
	$(MKDIR) $(PATHBIN)

$(PATHDYLIB):
	cargo build --manifest-path=../Cargo.toml --package=rcrypto-sys

clean:
	$(CLEANUP) $(PATHBIN)*.o
	$(CLEANUP) $(PATHBUILD)*.$(TARGET_EXTENSION)
	$(CLEANUP) $(PATHBUILD)*.txt

.PRECIOUS: $(PATHB)Test%.$(TARGET_EXTENSION)
.PRECIOUS: $(PATHR)%.txt
