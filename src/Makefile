all: subprojects-zlib plugins

-include ../config.mk
include ../ghidra/deps.mk

R2GHIDRA_SRCS= R2Architecture.cpp
R2GHIDRA_SRCS+=PcodeFixupPreprocessor.cpp
R2GHIDRA_SRCS+=R2LoadImage.cpp
R2GHIDRA_SRCS+=R2Scope.cpp
R2GHIDRA_SRCS+=R2TypeFactory.cpp
R2GHIDRA_SRCS+=R2CommentDatabase.cpp
R2GHIDRA_SRCS+=CodeXMLParse.cpp
R2GHIDRA_SRCS+=ArchMap.cpp
R2GHIDRA_SRCS+=R2PrintC.cpp
R2GHIDRA_SRCS+=RCoreMutex.cpp

R2GHIDRA_SRCS+=SleighAnalValue.cpp
R2GHIDRA_SRCS+=SleighAsm.cpp
R2GHIDRA_SRCS+=SleighInstruction.cpp

# R2GHIDRA_SRCS= ArchMap.cpp CodeXMLParse.cpp R2Architecture.cpp R2CommentDatabase.cpp R2LoadImage.cpp
# R2GHIDRA_SRCS+= R2PrintC.cpp R2Scope.cpp R2TypeFactory.cpp RCoreMutex.cpp SleighAnalValue.cpp SleighAsm.cpp
# R2GHIDRA_SRCS+= SleighInstruction.cpp

R2G_PLUG_SRCS= anal_ghidra.cpp core_ghidra.cpp
R2G_PLUG_SRCS+= anal_ghidra_plugin.o core_ghidra_plugin.o

PUGIXML_HOME=../subprojects/pugixml/src/
PUGIXML_CFLAGS=-I$(PUGIXML_HOME)
PUGIXML_SRCS= $(PUGIXML_HOME)/pugixml.cpp
PUGIXML_OBJS= $(PUGIXML_HOME)/pugixml.o
#PUGIXML_OBJS= pugixml.o

$(PUGIXML_OBJS): $(PUGIXML_SRCS)
	$(CXX) -c $(R2_LDFLAGS) $(CXXFLAGS) -o $@ $<

CXXFLAGS+=$(PUGIXML_CFLAGS)
# CXXFLAGS+=-DR2GHIDRA_SLEIGHHOME_DEFAULT=\"$(GHIDRA_HOME)\"

R2GHIDRA_OBJS=$(subst .cpp,.o,$(R2GHIDRA_SRCS))
R2G_PLUGIN_OBJS=$(subst .cpp,.o,$(R2G_PLUG_SRCS))

CFLAGS+=-DR2GHIDRA_SLEIGHHOME_DEFAULT=\"$(R2_USER_PLUGINS)/r2ghidra_sleigh\"
CFLAGS+=-w
CFLAGS+=-fPIC
CFLAGS+=-Wshadow
CFLAGS+=-I$(GHIDRA_DECOMPILER)
CFLAGS+=-I.
CFLAGS+=$(ZLIB_CFLAGS)

#CFLAGS+=-g -ggdb
#LDFLAGS+=-g -ggdb
#CXXFLAGS+=-g -ggdb

CXXFLAGS+=-std=c++20
CFLAGS+=$(R2_CFLAGS)

CXXFLAGS+=$(CFLAGS)

R2_LIBEXT=$(shell r2 -H R2_LIBEXT)
# TODO: rename to r2ghidra.$(R2_LIBEXT)
R2G_CORE_PLUGIN=core_ghidra.$(R2_LIBEXT)
R2G_ASM_PLUGIN=asm_ghidra.$(R2_LIBEXT)
R2G_ANAL_PLUGIN=anal_ghidra.$(R2_LIBEXT)

ifeq ($(R2_LIBEXT),)
Cannot run r2
endif

subprojects-zlib:
	$(MAKE) -C ../subprojects zlib-static

clean:
	rm -f *.o $(PUGIXML_HOME)/*.o
	rm -f *.o $(GHIDRA_DECOMPILER)/*.o
	rm -f $(R2G_CORE_PLUGIN) $(R2G_ASM_PLUGIN) $(R2G_ANAL_PLUGIN) sleighc

plugins: $(R2G_CORE_PLUGIN) sleighc
	$(MAKE) sign

deps=$(R2GHIDRA_OBJS) $(GHIDRA_OBJS) $(R2G_PLUGIN_OBJS) $(PUGIXML_OBJS)

asan:
	LDFLAGS="-fsanitize=address" CFLAGS="-fsanitize=address -g" $(MAKE) -j
	$(MAKE) user-install

$(R2G_CORE_PLUGIN): $(deps)
	$(CXX) -shared -o $@ $(R2GHIDRA_OBJS) $(GHIDRA_OBJS) $(PUGIXML_OBJS) core_ghidra.o \
		anal_ghidra.o core_ghidra_plugin.o anal_ghidra_plugin.o $(R2_LDFLAGS) $(ZLIB_LDFLAGS) $(LDFLAGS) $(CXXFLAGS)

$(R2G_ANAL_PLUGIN): $(deps)
	$(CXX) -shared $(GHIDRA_OBJS) $(PUGIXML_OBJS) anal_ghidra.o anal_ghidra_plugin.o \
		 $(R2GHIDRA_OBJS) $(R2_LDFLAGS) $(ZLIB_LDFLAGS) $(LDFLAGS) $(CXXFLAGS) -o $@

ifneq (,$(wildcard /usr/bin/codesign))
sign macsign:
	-codesign -f -s - *.dylib
else
sign macsign:
endif

%.o: %.cpp
	$(CXX) -fPIC $(CXXFLAGS) $(R2_CFLAGS) -c $<

PLUGDIR?=$(R2_LIBR_PLUGINS)

install:
	mkdir -p $(DESTDIR)$(BINDIR)
	cp -f sleighc $(DESTDIR)$(BINDIR)
	mkdir -p $(DESTDIR)$(PLUGDIR)
	for a in *.$(R2_LIBEXT) ; do rm -f "$(DESTDIR)/$(PLUGDIR)/$$a" ; done
	cp -f *.$(R2_LIBEXT) $(DESTDIR)$(PLUGDIR)
	rm -f $(DESTDIR)$(PLUGDIR)/asm*ghidra*.$(R2_LIBEXT)
	rm -f $(DESTDIR)$(PLUGDIR)/anal*ghidra*.$(R2_LIBEXT)
ifneq (,$(wildcard /usr/bin/codesign))
	-codesign -f -s - $(DESTDIR)$(PLUGDIR)/*.$(R2_LIBEXT)
endif

uninstall:
	rm -f $(PLUGDIR)/*ghidra*.$(R2_LIBEXT)
	rm -f $(DESTDIR)/$(BINDIR)/sleighc

user-install:
	rm -f $(PLUGDIR)/asm*ghidra*.$(R2_LIBEXT)
	rm -f $(PLUGDIR)/anal*ghidra*.$(R2_LIBEXT)
	$(MAKE) install PLUGDIR=$(R2_USER_PLUGINS) BINDIR=$(shell r2pm -H R2PM_BINDIR)

user-uninstall:
	$(MAKE) uninstall PLUGDIR=$(R2_USER_PLUGINS) BINDIR=$(shell r2pm -H R2PM_BINDIR)
