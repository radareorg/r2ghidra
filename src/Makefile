all: plugins

include ../config.mk
include ../ghidra/deps.mk


R2GHIDRA_SRCS= ArchMap.cpp CodeXMLParse.cpp R2Architecture.cpp R2CommentDatabase.cpp R2LoadImage.cpp
R2GHIDRA_SRCS+= R2PrintC.cpp R2Scope.cpp R2TypeFactory.cpp RCoreMutex.cpp SleighAnalValue.cpp SleighAsm.cpp
R2GHIDRA_SRCS+= SleighInstruction.cpp
R2G_PLUG_SRCS= anal_ghidra.cpp asm_ghidra.cpp core_ghidra.cpp

PUGIXML_HOME=../third-party/pugixml/src/
PUGIXML_CFLAGS=-I$(PUGIXML_HOME)
PUGIXML_SRCS= $(PUGIXML_HOME)/pugixml.cpp
PUGIXML_OBJS= $(PUGIXML_HOME)/pugixml.o
#PUGIXML_OBJS= pugixml.o

$(PUGIXML_OBJS): $(PUGIXML_SRCS)
	$(CXX) -c $(R2_LDFLAGS) $(CXXFLAGS) -o $@ $(R2GHIDRA_OBJS) $(GHIDRA_OBJS) $<

CXXFLAGS+=$(PUGIXML_CFLAGS)
# CXXFLAGS+=-DR2GHIDRA_SLEIGHHOME_DEFAULT=\"$(GHIDRA_HOME)\"

R2GHIDRA_OBJS=$(subst .cpp,.o,$(R2GHIDRA_SRCS))
R2G_PLUGIN_OBJS=$(subst .cpp,.o,$(R2G_PLUG_SRCS))

CXX=clang++

CFLAGS+=-DR2GHIDRA_SLEIGHHOME_DEFAULT=\"$(R2_USER_PLUGINS)/r2ghidra_sleigh\"
CFLAGS+=-w
CFLAGS+=-fPIC
CFLAGS+=-I$(GHIDRA_DECOMPILER)
CFLAGS+=-I.
ifeq ($(shell uname),FreeBSD)
CFLAGS+=-DHOST_ENDIAN=1
CFLAGS+=-Dint1=char
CFLAGS+=-Dint2=short
CFLAGS+=-Duint1=unsigned" char"
CFLAGS+=-Duint2=unsigned" short"
CFLAGS+=-Dint4=int
CFLAGS+=-Duint4=unsigned" long long"
CFLAGS+=-Dint8="long long"
CFLAGS+=-Duint8="unsigned long long"
CFLAGS+=-Duintm="unsigned long long"
CFLAGS+=-Duintp="unsigned long long"
endif

CXXFLAGS+=-std=c++11
CXXFLAGS+=$(CFLAGS)

R2_LIBEXT=$(shell r2 -H R2_LIBEXT)
R2G_CORE_PLUGIN=core_ghidra.$(R2_LIBEXT)
R2G_ASM_PLUGIN=asm_ghidra.$(R2_LIBEXT)
R2G_ANAL_PLUGIN=anal_ghidra.$(R2_LIBEXT)

clean:
	rm -f *.o $(GHIDRA_HOME)/*.o

plugins: $(R2G_CORE_PLUGIN) $(R2G_ASM_PLUGIN) $(R2G_ANAL_PLUGIN) sleighc

deps=$(R2GHIDRA_OBJS) $(GHIDRA_OBJS) $(R2G_PLUGIN_OBJS) $(PUGIXML_OBJS)

$(R2G_CORE_PLUGIN): $(deps)
	$(CXX) -shared $(R2_LDFLAGS) $(CXXFLAGS) -o $@ $(R2GHIDRA_OBJS) $(GHIDRA_OBJS) core_ghidra.o

$(R2G_ASM_PLUGIN): $(deps)
	$(CXX) -shared $(R2_LDFLAGS) $(CXXFLAGS) -o $@ $(R2GHIDRA_OBJS) $(GHIDRA_OBJS) asm_ghidra.o

$(R2G_ANAL_PLUGIN): $(deps)
	$(CXX) -shared $(R2_LDFLAGS) $(CXXFLAGS) -o $@ $(R2GHIDRA_OBJS) $(GHIDRA_OBJS) anal_ghidra.o

%.o: %.cpp
	$(CXX) -fPIC $(CXXFLAGS) $(R2_CFLAGS) -c $<

install:
	cp -f *.$(R2_LIBEXT) $(R2_USER_PLUGINS)

uninstall:
	rm -f $(R2_USER_PLUGINS)/*ghidra*.$(R2_LIBEXT)
