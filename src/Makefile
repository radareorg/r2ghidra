include ../config.mk
include ../ghidra/deps.mk

# PKGCONFIG=pkgconf
# PKGCONF=PKG_CONFIG_PATH=/tmp/r2/lib/pkgconfig $(PKGCONFIG)
# R2_CFLAGS=$(shell $(PKGCONF) --cflags r_core)
# R2_LDFLAGS=$(shell $(PKGCONF) --libs r_core)
# R2_USER_PLUGINS=$(shell r2 -H R2_USER_PLUGINS)


R2GHIDRA_SRCS= ArchMap.cpp CodeXMLParse.cpp R2Architecture.cpp R2CommentDatabase.cpp R2LoadImage.cpp
R2GHIDRA_SRCS+= R2PrintC.cpp R2Scope.cpp R2TypeFactory.cpp RCoreMutex.cpp SleighAnalValue.cpp SleighAsm.cpp
R2GHIDRA_SRCS+= SleighInstruction.cpp
R2G_PLUG_SRCS= anal_ghidra.cpp asm_ghidra.cpp core_ghidra.cpp

PUGIXML_HOME=../third-party/pugixml/src/
PUGIXML_CFLAGS=-I$(PUGIXML_HOME)
PUGIXML_OBJS= $(PUGIXML_HOME)/pugixml.o

CXXFLAGS+=$(PUGIXML_CFLAGS)
CXXFLAGS+=-DR2GHIDRA_SLEIGHHOME_DEFAULT=\"$(GHIDRA_HOME)\"

R2GHIDRA_OBJS=$(subst .cpp,.o,$(R2GHIDRA_SRCS))
R2G_PLUGIN_OBJS=$(subst .cpp,.o,$(R2G_PLUG_SRCS))

CXX=clang++
CXXFLAGS+=-fPIC
CXXFLAGS+=-std=c++11
CXXFLAGS+=-I$(GHIDRA_DECOMPILER)
CXXFLAGS+=-I.
ifeq (1,2)
## CXXFLAGS+=-DHOST_ENDIAN=1
CXXFLAGS+=-Dint2=short
CXXFLAGS+=-Duint2=unsigned" short"
CXXFLAGS+=-Dint4=int
CXXFLAGS+=-Duint4=unsigned" long long"
CXXFLAGS+=-Dint8="long long"
CXXFLAGS+=-Duint8="unsigned long long"
CXXFLAGS+=-Duintm="unsigned long long"
# needed for freebsd
# ------------------
# CXXFLAGS+=-Duintp=size_t
# CXXFLAGS+=-Duint1="unsigned char"
endif


EXT_SO=$(shell r2 -H R2_LIBEXT)
R2G_CORE_PLUGIN=core_ghidra.so
R2G_ASM_PLUGIN=asm_ghidra.so
R2G_ANAL_PLUGIN=anal_ghidra.so


all: plugins

clean:
	rm *.o $(GHIDRA_HOME)/*.o

plugins: $(R2G_CORE_PLUGIN) $(R2G_ASM_PLUGIN) $(R2G_ANAL_PLUGIN)

deps: $(R2GHIDRA_OBJS) $(GHIDRA_OBJS) $(R2G_PLUGIN_OBJS) $(PUGIXML_OBJS)

$(R2G_CORE_PLUGIN): deps
	$(CXX) -shared $(R2_LDFLAGS) $(CXXFLAGS) -o $@ $(R2GHIDRA_OBJS) pugixml.o $(GHIDRA_OBJS) core_ghidra.o

$(R2G_ASM_PLUGIN): deps
	$(CXX) -shared $(R2_LDFLAGS) $(CXXFLAGS) -o $@ $(R2GHIDRA_OBJS) $(GHIDRA_OBJS) asm_ghidra.o

$(R2G_ANAL_PLUGIN): deps
	$(CXX) -shared $(R2_LDFLAGS) $(CXXFLAGS) -o $@ $(R2GHIDRA_OBJS) $(GHIDRA_OBJS) anal_ghidra.o

%.o: %.cpp
	$(CXX) -fPIC $(CXXFLAGS) $(R2_CFLAGS) -c $<

install:
	cp -f *.$(EXT_SO) $(R2_USER_PLUGINS)

uninstall:
	rm -f $(R2_USER_PLUGINS)/*ghidra*.$(EXT_SO)
