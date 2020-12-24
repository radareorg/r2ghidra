all: plugins

-include ../config.mk
include ../ghidra/deps.mk


R2GHIDRA_SRCS= ArchMap.cpp CodeXMLParse.cpp R2Architecture.cpp R2CommentDatabase.cpp R2LoadImage.cpp
R2GHIDRA_SRCS+= R2PrintC.cpp R2Scope.cpp R2TypeFactory.cpp RCoreMutex.cpp SleighAnalValue.cpp SleighAsm.cpp
R2GHIDRA_SRCS+= SleighInstruction.cpp
R2G_PLUG_SRCS= anal_ghidra.cpp asm_ghidra.cpp core_ghidra.cpp

PUGIXML_HOME=../third-party/pugixml/src/
PUGIXML_CFLAGS=-I$(PUGIXML_HOME)
PUGIXML_SRCS= $(PUGIXML_HOME)/pugixml.cpp
PUGIXML_OBJS= $(PUGIXML_HOME)/pugixml.o

$(PUGIXML_OBJS): $(PUGIXML_SRCS)
	$(CXX) -c $(R2_LDFLAGS) $(CXXFLAGS) -o $@ $(GHIDRA_OBJS) $(GHIDRA_OBJS2) $<

CXXFLAGS+=$(PUGIXML_CFLAGS)
# CXXFLAGS+=-DR2GHIDRA_SLEIGHHOME_DEFAULT=\"$(GHIDRA_HOME)\"

R2GHIDRA_OBJS=$(subst .cpp,.o,$(R2GHIDRA_SRCS))
R2G_PLUGIN_OBJS=$(subst .cpp,.o,$(R2G_PLUG_SRCS))

CFLAGS+=-DR2GHIDRA_SLEIGHHOME_DEFAULT=\"$(R2_USER_PLUGINS)/r2ghidra_sleigh\"
CFLAGS+=-w
CFLAGS+=-fPIC
CFLAGS+=-I$(GHIDRA_DECOMPILER)
CFLAGS+=-I.

CXXFLAGS+=-std=c++11
CXXFLAGS+=$(CFLAGS)

R2_LIBEXT=$(shell r2 -H R2_LIBEXT)
R2G_CORE_PLUGIN=core_ghidra.$(R2_LIBEXT)
R2G_ASM_PLUGIN=asm_ghidra.$(R2_LIBEXT)
R2G_ANAL_PLUGIN=anal_ghidra.$(R2_LIBEXT)

clean:
	rm -f *.o $(GHIDRA_HOME)/*.o

plugins: $(R2G_CORE_PLUGIN) $(R2G_ASM_PLUGIN) $(R2G_ANAL_PLUGIN) sleighc

deps=$(R2GHIDRA_OBJS) $(GHIDRA_OBJS) $(GHIDRA_OBJS2) $(R2G_PLUGIN_OBJS) $(PUGIXML_OBJS)

$(R2GHIDRA_OBJS): grammars

$(R2G_CORE_PLUGIN): $(deps)
	$(CXX) -shared $(R2_LDFLAGS) $(CXXFLAGS) -o $@ $(R2GHIDRA_OBJS) $(GHIDRA_OBJS) $(GHIDRA_OBJS2) $(PUGIXML_OBJS) core_ghidra.o

$(R2G_ASM_PLUGIN): $(deps)
	$(CXX) -shared $(R2_LDFLAGS) $(CXXFLAGS) -o $@ $(R2GHIDRA_OBJS) $(GHIDRA_OBJS) $(GHIDRA_OBJS2) $(PUGIXML_OBJS) asm_ghidra.o

$(R2G_ANAL_PLUGIN): $(deps)
	$(CXX) -shared $(R2_LDFLAGS) $(CXXFLAGS) -o $@ $(R2GHIDRA_OBJS) $(GHIDRA_OBJS) $(GHIDRA_OBJS2) $(PUGIXML_OBJS) anal_ghidra.o

%.o: %.cpp
	$(CXX) -fPIC $(CXXFLAGS) $(R2_CFLAGS) -c $<

install:
	cp -f *.$(R2_LIBEXT) $(R2_USER_PLUGINS)

uninstall:
	rm -f $(R2_USER_PLUGINS)/*ghidra*.$(R2_LIBEXT)
