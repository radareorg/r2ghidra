project('ghidra-native', 'cpp', meson_version : '>=0.60.0', version : '7c1f8b6975a685f785d4801b794715d9a6a55b19')

sources = [
  'src/decompiler/action.cc',
  'src/decompiler/address.cc',
  'src/decompiler/architecture.cc',
  #e/src/decompiler/bfd_arch.cc',
  'src/decompiler/block.cc',
  'src/decompiler/blockaction.cc',
  # 'src/decompiler/callgraph.cc', # debug
  'src/decompiler/capability.cc',
  'src/decompiler/cast.cc',
  #e/src/decompiler/codedata.cc',
  'src/decompiler/comment.cc',
  'src/decompiler/comment_ghidra.cc',
  'src/decompiler/condexe.cc',
  #e/src/decompiler/consolemain.cc',
  'src/decompiler/context.cc',
  'src/decompiler/coreaction.cc',
  'src/decompiler/cover.cc',
  'src/decompiler/cpool.cc',
  'src/decompiler/cpool_ghidra.cc',
  'src/decompiler/crc32.cc',
  'src/decompiler/database.cc',
  'src/decompiler/database_ghidra.cc',
  'src/decompiler/double.cc',
  'src/decompiler/dynamic.cc',
  'src/decompiler/emulate.cc',
  'src/decompiler/emulateutil.cc',
  'src/decompiler/filemanage.cc',
  'src/decompiler/float.cc',
  'src/decompiler/flow.cc',
  'src/decompiler/fspec.cc',
  'src/decompiler/multiprecision.cc',
  'src/decompiler/funcdata.cc',
  'src/decompiler/funcdata_block.cc',
  'src/decompiler/funcdata_op.cc',
  'src/decompiler/funcdata_varnode.cc',
  'src/decompiler/unionresolve.cc',
  'src/decompiler/ghidra_arch.cc',
  'src/decompiler/ghidra_context.cc',
  #e/src/decompiler/ghidra_process.cc',
  'src/decompiler/ghidra_translate.cc',
  'src/decompiler/globalcontext.cc',
  # 'src/decompiler/grammar.cc', # used by diagnostic mode
  'src/decompiler/graph.cc',
  'src/decompiler/heritage.cc',
   # 'src/decompiler/ifacedecomp.cc', # debug
   #'src/decompiler/testfunction.cc',
  # 'src/decompiler/ifaceterm.cc',
  'src/decompiler/inject_ghidra.cc',
  'src/decompiler/inject_sleigh.cc',
  # 'src/decompiler/interface.cc', # debug
  'src/decompiler/jumptable.cc',
  'src/decompiler/libdecomp.cc',
  'src/decompiler/loadimage.cc',
  #e/src/decompiler/loadimage_bfd.cc',
  'src/decompiler/loadimage_ghidra.cc',
  'src/decompiler/loadimage_xml.cc',
  'src/decompiler/memstate.cc',
  'src/decompiler/merge.cc',
  'src/decompiler/op.cc',
  'src/decompiler/opbehavior.cc',
  'src/decompiler/opcodes.cc',
  'src/decompiler/options.cc',
  'src/decompiler/override.cc',
  'src/decompiler/paramid.cc',
  'src/decompiler/pcodecompile.cc',
  'src/decompiler/pcodeinject.cc',
  'src/decompiler/pcodeparse.cc',
  'src/decompiler/pcoderaw.cc',
  'src/decompiler/prefersplit.cc',
  'src/decompiler/prettyprint.cc',
  'src/decompiler/printc.cc',
  'src/decompiler/printjava.cc',
  'src/decompiler/printlanguage.cc',
  'src/decompiler/rangeutil.cc',
  'src/decompiler/raw_arch.cc',
  'src/decompiler/ruleaction.cc',
  'src/decompiler/rulecompile.cc',
  'src/decompiler/compression.cc',
  'src/decompiler/slaformat.cc',
  'src/decompiler/semantics.cc',
  'src/decompiler/sleigh.cc',
  'src/decompiler/sleigh_arch.cc',
  'src/decompiler/sleighbase.cc',
  #e/src/decompiler/sleighexample.cc',
  #e/src/decompiler/slgh_compile.cc',
  #e/src/decompiler/slghparse.cc',
  'src/decompiler/slghpatexpress.cc',
  'src/decompiler/slghpattern.cc',
  #e/src/decompiler/slghscan.cc',
  'src/decompiler/slghsymbol.cc',
  'src/decompiler/marshal.cc',
  'src/decompiler/space.cc',
  'src/decompiler/string_ghidra.cc',
  'src/decompiler/stringmanage.cc',
  'src/decompiler/modelrules.cc',
  'src/decompiler/subflow.cc',
  'src/decompiler/transform.cc',
  'src/decompiler/translate.cc',
  'src/decompiler/type.cc',
  'src/decompiler/typegrp_ghidra.cc',
  'src/decompiler/typeop.cc',
  'src/decompiler/unify.cc',
  'src/decompiler/userop.cc',
  'src/decompiler/variable.cc',
  'src/decompiler/varmap.cc',
  'src/decompiler/varnode.cc',
  'src/decompiler/xml.cc',
  'src/decompiler/xml_arch.cc',
]

slgh_sources = [
  'src/decompiler/slgh_compile.cc',
  'src/decompiler/slghparse.cc',
  'src/decompiler/slghscan.cc',
]

zlib = dependency('zlib', version : '>=1.2.8', required: false)
if not zlib.found()
  zlib_proj = subproject('zlib', default_options: ['default_library=static', 'werror=false'])
  zlib = zlib_proj.get_variable('zlib_dep')
  meson.override_dependency('zlib', zlib)
endif

incs = include_directories('src/decompiler')

ghidra_static = static_library(
  'ghidra', sources,
  dependencies: zlib,
  include_directories: incs
)

slgh_static = static_library(
  'slgh', sources + slgh_sources,
  dependencies: zlib,
  include_directories: incs
)


