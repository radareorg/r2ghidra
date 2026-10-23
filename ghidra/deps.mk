# hardcoded for now
USE_BISON=0

# Use static zlib to avoid symbol conflicts with radare2's zlib
# On Linux, use -Bsymbolic to prevent symbol interposition
UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Linux)
ZLIB_LDFLAGS=-Wl,-Bsymbolic ../subprojects/zlib/libz.a
else
ZLIB_LDFLAGS=../subprojects/zlib/libz.a
endif
ZLIB_CFLAGS=-I../subprojects/zlib

# GHIDRA_HOME=../ghidra/ghidra/
# GHIDRA_DECOMPILER=$(GHIDRA_HOME)/Ghidra/Features/Decompiler/src/decompile/cpp
# GHIDRA_HOME=../ghidra-native
GHIDRA_HOME=../subprojects/ghidra-native
GHIDRA_DECOMPILER=$(GHIDRA_HOME)/src/decompiler

-include $(GHIDRA_HOME)/sources.mk
G_DECOMPILER=$(GHIDRA_EMBEDDED_SRCS)

ifeq ($(USE_BISON),1)
$(GHIDRA_DECOMPILER)/grammar.cc: $(GHIDRA_DECOMPILER)/grammar.y
	$(BISON) -p grammar -o $(GHIDRA_DECOMPILER)/grammar.cc $(GHIDRA_DECOMPILER)/grammar.y
	$(CXX) $(CXXFLAGS) $(LDFLAGS) -o $(GHIDRA_DECOMPILER)/grammar.o -c $(GHIDRA_DECOMPILER)/grammar.cc

$(GHIDRA_DECOMPILER)/ruleparser.cc: $(GHIDRA_DECOMPILER)/grammar.y
	$(BISON) -p ruleparser -o $(GHIDRA_DECOMPILER)/ruleparser.cc $(GHIDRA_DECOMPILER)/ruleparser.y
	$(CXX) $(CXXFLAGS) $(LDFLAGS) -o $(GHIDRA_DECOMPILER)/ruleparser.o -c $(GHIDRA_DECOMPILER)/ruleparser.cc

$(GHIDRA_DECOMPILER)/xml.cc: $(GHIDRA_DECOMPILER)/xml.y
	$(BISON) -p xml -o $(GHIDRA_DECOMPILER)/xml.cc $(GHIDRA_DECOMPILER)/xml.y
	$(CXX) $(CXXFLAGS) $(LDFLAGS) -o $(GHIDRA_DECOMPILER)/xml.o -c $(GHIDRA_DECOMPILER)/xml.cc

$(GHIDRA_DECOMPILER)/pcodeparse.cc: $(GHIDRA_DECOMPILER)/pcodeparse.y
	$(BISON) -p pcodeparser -o $(GHIDRA_DECOMPILER)/pcodeparse.cc $(GHIDRA_DECOMPILER)/pcodeparse.y
	$(CXX) $(CXXFLAGS) $(LDFLAGS) -o $(GHIDRA_DECOMPILER)/pcodeparse.o -c $(GHIDRA_DECOMPILER)/pcodeparse.cc

$(GHIDRA_DECOMPILER)/slghparse.cc: $(GHIDRA_DECOMPILER)/slghparse.y
	echo '#include \"slghparse.hpp\"' > $(GHIDRA_DECOMPILER)/slghparse.tab.hpp
	$(BISON) -d -o $(GHIDRA_DECOMPILER)/slghparse.tab.hh $(GHIDRA_DECOMPILER)/slghparse.y
	$(BISON) -o $(GHIDRA_DECOMPILER)/slghparse.cc $(GHIDRA_DECOMPILER)/slghparse.y

.PHONY: $(GHIDRA_DECOMPILER)/slghparse.cc
.PHONY: $(GHIDRA_DECOMPILER)/slghscan.cc

$(GHIDRA_DECOMPILER)/slghscan.cc: $(GHIDRA_DECOMPILER)/slghscan.l $(GHIDRA_DECOMPILER)/slghparse.cc
	$(FLEX) --header-file=$(GHIDRA_DECOMPILER)/slghscan.tab.hh -o $(GHIDRA_DECOMPILER)/slghscan.cc $(GHIDRA_DECOMPILER)/slghscan.l
endif

GHIDRA_SRCS=$(addprefix $(GHIDRA_DECOMPILER)/,$(G_DECOMPILER))
GHIDRA_OBJS+=$(subst .cc,.o,$(GHIDRA_SRCS))

sleigh: sleighc
	$(SLEIGHC) $(SPECFILE) $(SLAFILE)

SLEIGHTC_OBJS=$(addprefix $(GHIDRA_DECOMPILER)/,$(GHIDRA_SLEIGH_COMPILER_SRCS:.cc=.o))

sleighc: $(SLEIGHTC_OBJS) $(GHIDRA_OBJS)
	$(CXX) $(CXXFLAGS) -o sleighc $(SLEIGHTC_OBJS) $(GHIDRA_OBJS) $(ZLIB_LDFLAGS) $(LDFLAGS)

GHIDRA_SLEIGH_HOME=$(GHIDRA_HOME)/src/Processors
GHIDRA_SLEIGH_SLASPECS=$(GHIDRA_SLEIGH_HOME)/*.slaspec
GHIDRA_SLEIGH_FILES=$(GHIDRA_SLEIGH_HOME)/*.cspec
GHIDRA_SLEIGH_FILES+=$(GHIDRA_SLEIGH_HOME)/*.ldefs
GHIDRA_SLEIGH_FILES+=$(GHIDRA_SLEIGH_HOME)/*.pspec

../ghidra-processors.txt: ../ghidra-processors.txt.default
	cp -f ../ghidra-processors.txt.default ../ghidra-processors.txt

sleigh-build-serial: sleighc ../ghidra-processors.txt
	for a in DATA $(shell cat ../ghidra-processors.txt) ; do ./sleighc -a $(GHIDRA_SLEIGH_HOME)/$$a ; done

sleigh-build: sleighc ../ghidra-processors.txt
	for a in DATA $(shell cat ../ghidra-processors.txt) ; do ./sleighc -a $(GHIDRA_SLEIGH_HOME)/$$a & done

GHIDRA_PROCS=$(GHIDRA_SLEIGH_HOME)/*/*/*

sleigh-install: ../ghidra-processors.txt
	mkdir -p "$(D)"
	for a in DATA $(shell cat ../ghidra-processors.txt) ; do \
		for b in cspec ldefs sla pspec ; do \
			cp -f $(GHIDRA_SLEIGH_HOME)/$$a/*/*/*.$$b "$(D)"; \
		done ;\
	done

sleigh-uninstall:
	rm -rf "$(D)"
