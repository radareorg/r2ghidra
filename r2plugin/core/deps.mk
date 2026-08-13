# Statically link the r2ghidra core plugin (and the ghidra-native
# decompiler) into libr_core. This file is included from
# libr/core/Makefile via STATIC_CORE_PLUGINS, so it runs with
# radare2/libr/core as the working directory.
#
# Run 'make -C $(R2GHIDRA_XPS_WD)/r2plugin prepare' once to fetch the
# ghidra-native and zlib subprojects and generate config.h.

R2GHIDRA_XPS_WD=$(LIBR)/xps/p/r2ghidra
R2GHIDRA_XPS_DEC=$(R2GHIDRA_XPS_WD)/subprojects/ghidra-native/src/decompiler
R2GHIDRA_XPS_ZLIB=$(R2GHIDRA_XPS_WD)/subprojects/zlib
R2GHIDRA_XPS_OBD=$(R2GHIDRA_XPS_WD)/r2plugin/obj

ifeq ($(filter clean mrproper,$(MAKECMDGOALS)),)
ifeq ($(wildcard $(R2GHIDRA_XPS_DEC)/marshal.cc),)
$(error r2ghidra: ghidra-native sources not found. Run: make -C $(R2GHIDRA_XPS_WD)/r2plugin prepare)
endif
endif

R2GHIDRA_XPS_CXX_SRCS=\
	R2Architecture.cpp \
	PcodeFixupPreprocessor.cpp \
	R2LoadImage.cpp \
	R2Scope.cpp \
	R2TypeFactory.cpp \
	R2CommentDatabase.cpp \
	CodeXMLParse.cpp \
	ArchMap.cpp \
	R2PrintC.cpp \
	RCoreMutex.cpp \
	r2harvest.cpp \
	SleighAnalValue.cpp \
	SleighAsm.cpp \
	SleighInstruction.cpp \
	anal_ghidra.cpp \
	core_ghidra.cpp

R2GHIDRA_XPS_C_SRCS=\
	anal_ghidra_plugin.c \
	core_ghidra_plugin.c

# Keep in sync with ghidra/deps.mk (G_DECOMPILER with USE_BISON=0)
R2GHIDRA_XPS_DEC_SRCS=\
	marshal.cc space.cc float.cc address.cc pcoderaw.cc \
	translate.cc opcodes.cc globalcontext.cc \
	capability.cc architecture.cc options.cc graph.cc \
	cover.cc block.cc cast.cc typeop.cc database.cc \
	cpool.cc comment.cc stringmanage.cc modelrules.cc fspec.cc action.cc loadimage.cc \
	varnode.cc op.cc type.cc variable.cc varmap.cc \
	jumptable.cc emulate.cc emulateutil.cc flow.cc userop.cc expression.cc \
	multiprecision.cc funcdata.cc funcdata_block.cc funcdata_varnode.cc \
	funcdata_op.cc unionresolve.cc pcodeinject.cc heritage.cc prefersplit.cc \
	rangeutil.cc ruleaction.cc subflow.cc blockaction.cc \
	merge.cc double.cc coreaction.cc condexe.cc override.cc \
	dynamic.cc crc32.cc prettyprint.cc printlanguage.cc \
	printc.cc printjava.cc memstate.cc opbehavior.cc \
	paramid.cc transform.cc string_ghidra.cc constseq.cc \
	ghidra_arch.cc inject_ghidra.cc ghidra_translate.cc \
	loadimage_ghidra.cc typegrp_ghidra.cc database_ghidra.cc \
	ghidra_context.cc cpool_ghidra.cc comment_ghidra.cc \
	grammar.cc xml.cc pcodeparse.cc libdecomp.cc \
	sleigh_arch.cc sleigh.cc inject_sleigh.cc pcodecompile.cc \
	sleighbase.cc slghsymbol.cc slghpatexpress.cc slghpattern.cc \
	semantics.cc context.cc slaformat.cc compression.cc filemanage.cc

R2GHIDRA_XPS_ZLIB_SRCS=\
	adler32.c compress.c crc32.c deflate.c gzclose.c gzlib.c \
	gzread.c gzwrite.c infback.c inffast.c inflate.c inftrees.c \
	trees.c uncompr.c zutil.c

R2GHIDRA_XPS_OBJS=$(addprefix $(R2GHIDRA_XPS_OBD)/src_,$(R2GHIDRA_XPS_CXX_SRCS:.cpp=.o))
R2GHIDRA_XPS_OBJS+=$(addprefix $(R2GHIDRA_XPS_OBD)/src_,$(R2GHIDRA_XPS_C_SRCS:.c=.o))
R2GHIDRA_XPS_OBJS+=$(addprefix $(R2GHIDRA_XPS_OBD)/dec_,$(R2GHIDRA_XPS_DEC_SRCS:.cc=.o))
ifeq ($(COMPILER),wasi)
# radare2's wasi build already bundles zlib (otezip); linking a second copy
# makes wasm-ld fail on duplicate symbols. otezip only exports the *Init2_
# entrypoints, so provide the classic inflateInit_/deflateInit_ shims.
R2GHIDRA_XPS_OBJS+=$(R2GHIDRA_XPS_OBD)/z_compat.o
$(R2GHIDRA_XPS_OBD)/z_compat.o: $(R2GHIDRA_XPS_WD)/r2plugin/wasi/zlib_compat.c
	@mkdir -p $(dir $@)
	$(CC) -c $(CFLAGS) $(R2GHIDRA_XPS_CFLAGS) -o $@ $<
else
R2GHIDRA_XPS_OBJS+=$(addprefix $(R2GHIDRA_XPS_OBD)/z_,$(R2GHIDRA_XPS_ZLIB_SRCS:.c=.o))
endif

EXTERNAL_STATIC_OBJS+=$(R2GHIDRA_XPS_OBJS)

ifeq ($(shell uname),Darwin)
LDFLAGS+=-lc++
else
LDFLAGS+=-lstdc++ -lm
endif

R2GHIDRA_XPS_CFLAGS=-I$(R2GHIDRA_XPS_WD)/src -I$(R2GHIDRA_XPS_DEC) -I$(R2GHIDRA_XPS_ZLIB)
R2GHIDRA_XPS_CFLAGS+=-DNDEBUG -fPIC -fvisibility=hidden -w
ifeq ($(COMPILER),wasi)
# inside the wasmer sandbox the sleigh files are preopened at /sleigh
R2GHIDRA_XPS_CFLAGS+=-DR2GHIDRA_SLEIGHHOME_DEFAULT=\"/sleigh\"
endif
R2GHIDRA_XPS_CXXFLAGS=$(R2GHIDRA_XPS_CFLAGS) -std=c++20

$(R2GHIDRA_XPS_OBD)/src_%.o: $(R2GHIDRA_XPS_WD)/src/%.cpp
	@mkdir -p $(dir $@)
	$(CXX) -c $(CFLAGS) $(R2GHIDRA_XPS_CXXFLAGS) -o $@ $<

$(R2GHIDRA_XPS_OBD)/src_%.o: $(R2GHIDRA_XPS_WD)/src/%.c
	@mkdir -p $(dir $@)
	$(CC) -c $(CFLAGS) $(R2GHIDRA_XPS_CFLAGS) -o $@ $<

$(R2GHIDRA_XPS_OBD)/dec_%.o: $(R2GHIDRA_XPS_DEC)/%.cc
	@mkdir -p $(dir $@)
	$(CXX) -c $(CFLAGS) $(R2GHIDRA_XPS_CXXFLAGS) -o $@ $<

$(R2GHIDRA_XPS_OBD)/z_%.o: $(R2GHIDRA_XPS_ZLIB)/%.c
	@mkdir -p $(dir $@)
	$(CC) -c $(CFLAGS) $(R2GHIDRA_XPS_CFLAGS) -o $@ $<

$(R2GHIDRA_XPS_WD)/config.h: $(R2GHIDRA_XPS_WD)/config.h.acr
	$(MAKE) -C $(R2GHIDRA_XPS_WD)/r2plugin ../config.h

$(R2GHIDRA_XPS_OBD)/src_core_ghidra_plugin.o: $(R2GHIDRA_XPS_WD)/config.h

$(addprefix $(R2GHIDRA_XPS_OBD)/src_,$(R2GHIDRA_XPS_CXX_SRCS:.cpp=.o)): $(wildcard $(R2GHIDRA_XPS_WD)/src/*.h)
