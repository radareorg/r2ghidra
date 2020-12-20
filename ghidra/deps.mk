GHIDRA_HOME=../ghidra/ghidra/
GHIDRA_DECOMPILER=$(GHIDRA_HOME)/Ghidra/Features/Decompiler/src/decompile/cpp

G_DECOMPILER= space.cc float.cc address.cc pcoderaw.cc
G_DECOMPILER+=translate.cc opcodes.cc globalcontext.cc
G_DECOMPILER+= capability.cc architecture.cc options.cc graph.cc
G_DECOMPILER+= cover.cc block.cc cast.cc typeop.cc database.cc
G_DECOMPILER+= cpool.cc comment.cc fspec.cc action.cc loadimage.cc
G_DECOMPILER+= varnode.cc op.cc type.cc variable.cc varmap.cc
G_DECOMPILER+= jumptable.cc emulate.cc emulateutil.cc flow.cc userop.cc
G_DECOMPILER+= funcdata.cc funcdata_block.cc funcdata_varnode.cc
G_DECOMPILER+= funcdata_op.cc pcodeinject.cc heritage.cc prefersplit.cc
G_DECOMPILER+= rangeutil.cc ruleaction.cc subflow.cc blockaction.cc
G_DECOMPILER+= merge.cc double.cc coreaction.cc condexe.cc override.cc
G_DECOMPILER+= dynamic.cc crc32.cc prettyprint.cc printlanguage.cc
G_DECOMPILER+= printc.cc printjava.cc memstate.cc opbehavior.cc
G_DECOMPILER+= paramid.cc transform.cc string_ghidra.cc stringmanage.cc

GHIDRA_SRCS=$(addprefix $(GHIDRA_DECOMPILER),$(G_DECOMPILER))
GHIDRA_OBJS+=$(subst .cc,.o,$(GHIDRA_SRCS))

GHIDRA_LIBDECOMP_SRCS=libdecomp.cc
GHIDRA_LIBDECOMP_OBJS+=$(subst .cc,.o,$(GHIDRA_LIBDECOMP_SRCS))

GHIDRA_SLEIGH_COMPILER_SRCS=slgh_compile.cc
GHIDRA_SLEIGH_COMPILER_OBJS=$(subst .cc,.o,$(GHIDRA_SLEIGH_COMPILER_SRCS))
