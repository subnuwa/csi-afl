#
# CSI-AFL - makefile
# -----------------------------
#
# Written by Xiaogang Zhu <xiaogangzhu@swin.edu.au>
#
# Based on AFL (american fuzzy lop) by Michal Zalewski <lcamtuf@google.com>
# 
# ------------Original copyright below------------
# 
# Copyright 2013, 2014, 2015, 2016, 2017 Google Inc. All rights reserved.
# 
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
# 
#   http://www.apache.org/licenses/LICENSE-2.0
#

##################################################################

# var- edit DYN_ROOT accordingly

DYN_ROOT 	= /home/xgzhu/apps/dyninstShadow/thirdparty/dyninst-10.1.0/install
# These should point to where libelf and libdwarf are installed
# LOCAL_INC = /usr/local/include
# LOCAL_LIBS = /usr/local/lib
# TBB_INC = $(DYN_ROOT)/tbb/include
DYNINST_INCLUDE = $(DYN_ROOT)/include
DYNINST_LIB =  $(DYN_ROOT)/lib

CC 			= gcc 
CXX 		= g++
CXXFLAGS 	= -g -Wall -O3 -std=c++11
LIBFLAGS 	= -fpic -shared
LDFLAGS 	= -I$(DYNINST_INCLUDE)  -L$(DYNINST_LIB) \
					-lcommon -ldyninstAPI -lboost_system -linstructionAPI -lstdc++fs \
					-lparseAPI -lsymtabAPI
# -liberty -I$(TBB_INC) -I$(LOCAL_INC) -L$(LOCAL_LIBS) -I/usr/include



##################################################################

PROGNAME    = csi-afl
VERSION     = $(shell grep '^\#define VERSION ' config.h | cut -d '"' -f2)

PREFIX     ?= /usr/local
BIN_PATH    = $(PREFIX)/bin
HELPER_PATH = $(PREFIX)/lib/afl
DOC_PATH    = $(PREFIX)/share/doc/afl
MISC_PATH   = $(PREFIX)/share/afl

# PROGS intentionally omit untracer-as, which gets installed elsewhere.

PROGS       = csi-afl libCSIDyninst CSIDyninst afl-showmap
SH_PROGS    = afl-plot

CFLAGS     ?= -O3 -funroll-loops
CFLAGS     += -Wall -D_FORTIFY_SOURCE=2 -g -Wno-pointer-sign \
	      -DAFL_PATH=\"$(HELPER_PATH)\" -DDOC_PATH=\"$(DOC_PATH)\" \
	      -DBIN_PATH=\"$(BIN_PATH)\"

ifneq "$(filter Linux GNU%,$(shell uname))" ""
  LDFLAGS  += -ldl
endif


COMM_HDR    = alloc-inl.h config.h debug.h types.h instConfig.h

all: test_x86 $(PROGS) all_done

ifndef AFL_NO_X86

test_x86:
	@echo "[*] Checking for the ability to compile x86 code..."
	@echo 'main() { __asm__("xorb %al, %al"); }' | $(CC) -w -x c - -o .test || ( echo; echo "Oops, looks like your compiler can't generate x86 code."; echo; echo "Don't panic! You can use the LLVM or QEMU mode, but see docs/INSTALL first."; echo "(To ignore this error, set AFL_NO_X86=1 and try again.)"; echo; exit 1 )
	@rm -f .test
	@echo "[+] Everything seems to be working, ready to compile."

else

test_x86:
	@echo "[!] Note: skipping x86 compilation checks (AFL_NO_X86 set)."

endif

# CSI dependencies

csi-afl: csi-afl.c $(COMM_HDR) | test_x86
	$(CC) $(CFLAGS) $@.c -o $@ $(LDFLAGS)

libCSIDyninst: libCSIDyninst.cpp
	$(CXX) $(CXXFLAGS) -o libCSIDyninst.so libCSIDyninst.cpp $(LDFLAGS) $(LIBFLAGS)

CSIDyninst: CSIDyninst.cpp
	$(CXX) -Wl,-rpath-link,$(DYN_ROOT)/lib -Wl,-rpath-link,$(DYN_ROOT)/include $(CXXFLAGS) -o CSIDyninst CSIDyninst.cpp $(LDFLAGS)



afl-showmap: afl-showmap.c $(COMM_HDR) | test_x86
	$(CC) $(CFLAGS) $@.c -o $@ $(LDFLAGS)



all_done: 
	@echo "[+] All done! Be sure to review README - it's pretty short and useful."
	
.NOTPARALLEL: clean

clean:
	rm -f $(PROGS) *.o *~ a.out core core.[1-9][0-9]* *.stackdump test .test *.so



publish: clean
	test "`basename $$PWD`" = "afl" || exit 1
	test -f ~/www/afl/releases/$(PROGNAME)-$(VERSION).tgz; if [ "$$?" = "0" ]; then echo; echo "Change program version in config.h, mmkay?"; echo; exit 1; fi
	cd ..; rm -rf $(PROGNAME)-$(VERSION); cp -pr $(PROGNAME) $(PROGNAME)-$(VERSION); \
	  tar -cvz -f ~/www/afl/releases/$(PROGNAME)-$(VERSION).tgz $(PROGNAME)-$(VERSION)
	chmod 644 ~/www/afl/releases/$(PROGNAME)-$(VERSION).tgz
	( cd ~/www/afl/releases/; ln -s -f $(PROGNAME)-$(VERSION).tgz $(PROGNAME)-latest.tgz )
	cat docs/README >~/www/afl/README.txt
	cat docs/status_screen.txt >~/www/afl/status_screen.txt
	cat docs/historical_notes.txt >~/www/afl/historical_notes.txt
	cat docs/technical_details.txt >~/www/afl/technical_details.txt
	cat docs/ChangeLog >~/www/afl/ChangeLog.txt
	cat docs/QuickStartGuide.txt >~/www/afl/QuickStartGuide.txt
	echo -n "$(VERSION)" >~/www/afl/version.txt
