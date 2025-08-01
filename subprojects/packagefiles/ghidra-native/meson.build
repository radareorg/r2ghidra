project('ghidra-native', 'cpp', meson_version : '>=0.60.0', version : 'd2242691bf45a12e3ea483a4789f825af4651506')

base_sources = [
  'src/decompiler/marshal.cc',
  'src/decompiler/space.cc',
  'src/decompiler/float.cc',
  'src/decompiler/address.cc',
  'src/decompiler/pcoderaw.cc',
  'src/decompiler/translate.cc',
  'src/decompiler/opcodes.cc',
  'src/decompiler/globalcontext.cc',
  'src/decompiler/xml.cc',
]

decompiler_sources = [
  'src/decompiler/capability.cc',
  'src/decompiler/architecture.cc',
  'src/decompiler/options.cc',
  'src/decompiler/graph.cc',
  'src/decompiler/cover.cc',
  'src/decompiler/block.cc',
  'src/decompiler/cast.cc',
  'src/decompiler/typeop.cc',
  'src/decompiler/database.cc',
  'src/decompiler/cpool.cc',
  'src/decompiler/comment.cc',
  'src/decompiler/stringmanage.cc',
  'src/decompiler/modelrules.cc',
  'src/decompiler/fspec.cc',
  'src/decompiler/action.cc',
  'src/decompiler/loadimage.cc',
  'src/decompiler/varnode.cc',
  'src/decompiler/op.cc',
  'src/decompiler/type.cc',
  'src/decompiler/variable.cc',
  'src/decompiler/varmap.cc',
  'src/decompiler/jumptable.cc',
  'src/decompiler/emulate.cc',
  'src/decompiler/emulateutil.cc',
  'src/decompiler/flow.cc',
  'src/decompiler/userop.cc',
  'src/decompiler/multiprecision.cc',
  'src/decompiler/funcdata.cc',
  'src/decompiler/funcdata_block.cc',
  'src/decompiler/funcdata_varnode.cc',
  'src/decompiler/unionresolve.cc',
  'src/decompiler/funcdata_op.cc',
  'src/decompiler/pcodeinject.cc',
  'src/decompiler/heritage.cc',
  'src/decompiler/prefersplit.cc',
  'src/decompiler/rangeutil.cc',
  'src/decompiler/ruleaction.cc',
  'src/decompiler/subflow.cc',
  'src/decompiler/transform.cc',
  'src/decompiler/blockaction.cc',
  'src/decompiler/merge.cc',
  'src/decompiler/double.cc',
  'src/decompiler/coreaction.cc',
  'src/decompiler/condexe.cc',
  'src/decompiler/override.cc',
  'src/decompiler/dynamic.cc',
  'src/decompiler/crc32.cc',
  'src/decompiler/prettyprint.cc',
  'src/decompiler/printlanguage.cc',
  'src/decompiler/printc.cc',
  'src/decompiler/printjava.cc',
  'src/decompiler/memstate.cc',
  'src/decompiler/opbehavior.cc',
  'src/decompiler/paramid.cc',
  'src/decompiler/string_ghidra.cc',
  'src/decompiler/constseq.cc',
]

libdecomp_sources = [
  'src/decompiler/libdecomp.cc',
]

ghidra_sources = [
  'src/decompiler/ghidra_process.cc',
  'src/decompiler/ghidra_arch.cc',
  'src/decompiler/loadimage_ghidra.cc',
  'src/decompiler/typegrp_ghidra.cc',
  'src/decompiler/database_ghidra.cc',
  'src/decompiler/ghidra_context.cc',
  'src/decompiler/cpool_ghidra.cc',
  'src/decompiler/comment_ghidra.cc',
  'src/decompiler/inject_ghidra.cc',
  'src/decompiler/ghidra_translate.cc',
]

slgh_sources = [
  'src/decompiler/sleigh.cc',
  'src/decompiler/sleigh_arch.cc',
  'src/decompiler/inject_sleigh.cc',
  'src/decompiler/pcodecompile.cc',
  'src/decompiler/sleighbase.cc',
  'src/decompiler/slghsymbol.cc',
  'src/decompiler/slghpatexpress.cc',
  'src/decompiler/slghpattern.cc',
  'src/decompiler/semantics.cc',
  'src/decompiler/context.cc',
  'src/decompiler/slaformat.cc',
  'src/decompiler/compression.cc',
  'src/decompiler/filemanage.cc',

  'src/decompiler/pcodeparse.cc',
  'src/decompiler/grammar.cc',
]

sleigh_compiler_sources = [
  'src/decompiler/slgh_compile.cc',
  'src/decompiler/slgh_compile.hh',
  'src/decompiler/slghparse.hh',
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

ghidra_base_static = static_library('base',
  base_sources,
  include_directories: incs
)

ghidra_decompiler_static = static_library('ghidra',
  decompiler_sources,
  dependencies: zlib,
  link_with: ghidra_base_static,
  include_directories: incs
)

slgh_static = static_library('slgh',
  slgh_sources, # + sleigh_compiler_sources,
  dependencies: zlib,
  link_with: ghidra_base_static,
  include_directories: incs
)

libdecomp_static = static_library('libdecomp',
  libdecomp_sources,
  dependencies: zlib,
  link_with: [ghidra_decompiler_static, slgh_static],
  include_directories: incs
)

sleighc_exe = executable('sleighc',
  sleigh_compiler_sources,
  dependencies: zlib,
  link_with: slgh_static,
  include_directories: incs,
  override_options : ['c_std=c11', 'cpp_std=c++14'],
  install: true
)
