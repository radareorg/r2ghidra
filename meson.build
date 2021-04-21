project(
  'r2ghidra',
  'cpp',
license : 'LGPL3',
meson_version : '>=0.50.1',
version : '5.2.1',
default_options : ['c_std=c11', 'cpp_std=c++11']
)

pugixml_sources = [
  'third-party/pugixml/src/pugixml.cpp'
]

r2ghidra_sources = [
  'src/ArchMap.cpp',
  'src/CodeXMLParse.cpp',
  'src/R2Architecture.cpp',
  'src/R2CommentDatabase.cpp',
  'src/R2LoadImage.cpp',
  'src/R2PrintC.cpp',
  'src/R2Scope.cpp',
  'src/R2TypeFactory.cpp',
  'src/RCoreMutex.cpp',
  'src/SleighAnalValue.cpp',
  'src/SleighAsm.cpp',
  'src/SleighInstruction.cpp',
]

r_core = dependency('r_core')

ghidra_decompiler_sources = [
  'ghidra/ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/action.cc',
  'ghidra/ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/address.cc',
  'ghidra/ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/architecture.cc',
  # 'ghidra/ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/bfd_arch.cc',
  'ghidra/ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/block.cc',
  'ghidra/ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/blockaction.cc',
  'ghidra/ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/callgraph.cc',
  'ghidra/ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/capability.cc',
  'ghidra/ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/cast.cc',
  # 'ghidra/ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/codedata.cc',
  'ghidra/ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/comment.cc',
  'ghidra/ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/comment_ghidra.cc',
  'ghidra/ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/condexe.cc',
  # 'ghidra/ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/consolemain.cc',
  'ghidra/ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/context.cc',
  'ghidra/ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/coreaction.cc',
  'ghidra/ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/cover.cc',
  'ghidra/ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/cpool.cc',
  'ghidra/ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/cpool_ghidra.cc',
  'ghidra/ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/crc32.cc',
  'ghidra/ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/database.cc',
  'ghidra/ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/database_ghidra.cc',
  'ghidra/ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/double.cc',
  'ghidra/ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/dynamic.cc',
  'ghidra/ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/emulate.cc',
  'ghidra/ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/emulateutil.cc',
  'ghidra/ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/filemanage.cc',
  'ghidra/ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/float.cc',
  'ghidra/ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/flow.cc',
  'ghidra/ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/fspec.cc',
  'ghidra/ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/funcdata.cc',
  'ghidra/ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/funcdata_block.cc',
  'ghidra/ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/funcdata_op.cc',
  'ghidra/ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/funcdata_varnode.cc',
  'ghidra/ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/ghidra_arch.cc',
  'ghidra/ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/ghidra_context.cc',
  # 'ghidra/ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/ghidra_process.cc',
  'ghidra/ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/ghidra_translate.cc',
  'ghidra/ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/globalcontext.cc',
  'ghidra/ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/grammar.cc',
  'ghidra/ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/graph.cc',
  'ghidra/ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/heritage.cc',
  'ghidra/ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/ifacedecomp.cc',
  'ghidra/ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/ifaceterm.cc',
  'ghidra/ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/inject_ghidra.cc',
  'ghidra/ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/inject_sleigh.cc',
  'ghidra/ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/interface.cc',
  'ghidra/ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/jumptable.cc',
  'ghidra/ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/libdecomp.cc',
  'ghidra/ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/loadimage.cc',
  # 'ghidra/ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/loadimage_bfd.cc',
  'ghidra/ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/loadimage_ghidra.cc',
  'ghidra/ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/loadimage_xml.cc',
  'ghidra/ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/memstate.cc',
  'ghidra/ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/merge.cc',
  'ghidra/ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/op.cc',
  'ghidra/ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/opbehavior.cc',
  'ghidra/ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/opcodes.cc',
  'ghidra/ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/options.cc',
  'ghidra/ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/override.cc',
  'ghidra/ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/paramid.cc',
  'ghidra/ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/pcodecompile.cc',
  'ghidra/ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/pcodeinject.cc',
  'ghidra/ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/pcodeparse.cc',
  'ghidra/ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/pcoderaw.cc',
  'ghidra/ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/prefersplit.cc',
  'ghidra/ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/prettyprint.cc',
  'ghidra/ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/printc.cc',
  'ghidra/ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/printjava.cc',
  'ghidra/ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/printlanguage.cc',
  'ghidra/ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/rangeutil.cc',
  'ghidra/ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/raw_arch.cc',
  'ghidra/ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/ruleaction.cc',
  'ghidra/ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/rulecompile.cc',
  'ghidra/ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/semantics.cc',
  'ghidra/ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/sleigh.cc',
  'ghidra/ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/sleigh_arch.cc',
  'ghidra/ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/sleighbase.cc',
  # 'ghidra/ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/sleighexample.cc',
  # 'ghidra/ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/slgh_compile.cc',
  # 'ghidra/ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/slghparse.cc',
  'ghidra/ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/slghpatexpress.cc',
  'ghidra/ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/slghpattern.cc',
  # 'ghidra/ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/slghscan.cc',
  'ghidra/ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/slghsymbol.cc',
  'ghidra/ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/space.cc',
  'ghidra/ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/string_ghidra.cc',
  'ghidra/ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/stringmanage.cc',
  'ghidra/ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/subflow.cc',
  'ghidra/ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/transform.cc',
  'ghidra/ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/translate.cc',
  'ghidra/ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/type.cc',
  'ghidra/ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/typegrp_ghidra.cc',
  'ghidra/ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/typeop.cc',
  'ghidra/ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/unify.cc',
  'ghidra/ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/userop.cc',
  'ghidra/ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/variable.cc',
  'ghidra/ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/varmap.cc',
  'ghidra/ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/varnode.cc',
  'ghidra/ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/xml.cc',
  'ghidra/ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/xml_arch.cc',
]

r2ghidra_core_sources = [
  r2ghidra_sources,
  pugixml_sources,
  ghidra_decompiler_sources,
  'src/core_ghidra.cpp'
]
r2ghidra_asm_sources = [
  r2ghidra_sources,
  pugixml_sources,
  ghidra_decompiler_sources,
  'src/asm_ghidra.cpp',
]
r2ghidra_anal_sources = [
  r2ghidra_sources,
  pugixml_sources,
  ghidra_decompiler_sources,
  'src/anal_ghidra.cpp',
]

sleighc_sources = [
  r2ghidra_sources,
  pugixml_sources,
  'ghidra/ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/slgh_compile.cc',
  'ghidra/ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/slghparse.cc',
  'ghidra/ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/slghscan.cc',
  ghidra_decompiler_sources,
]

r2ghidra_incdirs = [
  'src',
  'third-party/pugixml/src/',
  'ghidra/ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/',
]

r2ghidra_core_plugin = library('core_r2ghidra',
  r2ghidra_core_sources,
  dependencies: [r_core],
  override_options : ['c_std=c11', 'cpp_std=c++11'],
  include_directories: r2ghidra_incdirs
)

r2ghidra_asm_plugin = library('asm_r2ghidra',
  r2ghidra_asm_sources,
  dependencies: [r_core],
  override_options : ['c_std=c11', 'cpp_std=c++11'],
  include_directories: r2ghidra_incdirs
)

r2ghidra_anal_plugin = library('anal_r2ghidra',
  r2ghidra_anal_sources,
  dependencies: [r_core],
  override_options : ['c_std=c11', 'cpp_std=c++11'],
  include_directories: r2ghidra_incdirs
)

sleighc_exe = executable('sleighc', sleighc_sources,
  include_directories: r2ghidra_incdirs,
  override_options : ['c_std=c11', 'cpp_std=c++11'],
  dependencies: [r_core],
)
