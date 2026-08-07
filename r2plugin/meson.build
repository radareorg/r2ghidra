# r2ghidra XPS integration for radare2.
# Included from libr/xps/p/meson.build when the r2ghidra repository lives
# under libr/xps/p/r2ghidra/. Compiles the ghidra-native decompiler and the
# r2ghidra core plugin into a static helper library and appends its objects
# to the r_core aggregate so the plugin is linked into libr_core.

core_plugins += ['r2ghidra']

add_languages('cpp', native: false)

r2g_fs = import('fs')

if not r2g_fs.is_file('../config.h') or not r2g_fs.is_file('../subprojects/ghidra-native/src/decompiler/marshal.cc') or not r2g_fs.is_file('../subprojects/zlib/zlib.h')
  r2g_prep = run_command('make', '-C', meson.current_source_dir(), 'prepare', check: false)
  if r2g_prep.returncode() != 0
    error('r2ghidra: prepare failed, run `make -C ' + meson.current_source_dir() + ' prepare` manually:\n' + r2g_prep.stderr())
  endif
endif

r2g_src_names = [
  'R2Architecture.cpp',
  'PcodeFixupPreprocessor.cpp',
  'R2LoadImage.cpp',
  'R2Scope.cpp',
  'R2TypeFactory.cpp',
  'R2CommentDatabase.cpp',
  'CodeXMLParse.cpp',
  'ArchMap.cpp',
  'R2PrintC.cpp',
  'RCoreMutex.cpp',
  'r2harvest.cpp',
  'SleighAnalValue.cpp',
  'SleighAsm.cpp',
  'SleighInstruction.cpp',
  'anal_ghidra.cpp',
  'core_ghidra.cpp',
  'anal_ghidra_plugin.c',
  'core_ghidra_plugin.c',
]

# Keep in sync with ghidra/deps.mk (G_DECOMPILER with USE_BISON=0)
r2g_dec_names = [
  'marshal.cc', 'space.cc', 'float.cc', 'address.cc', 'pcoderaw.cc',
  'translate.cc', 'opcodes.cc', 'globalcontext.cc',
  'capability.cc', 'architecture.cc', 'options.cc', 'graph.cc',
  'cover.cc', 'block.cc', 'cast.cc', 'typeop.cc', 'database.cc',
  'cpool.cc', 'comment.cc', 'stringmanage.cc', 'modelrules.cc',
  'fspec.cc', 'action.cc', 'loadimage.cc',
  'varnode.cc', 'op.cc', 'type.cc', 'variable.cc', 'varmap.cc',
  'jumptable.cc', 'emulate.cc', 'emulateutil.cc', 'flow.cc',
  'userop.cc', 'expression.cc',
  'multiprecision.cc', 'funcdata.cc', 'funcdata_block.cc',
  'funcdata_varnode.cc', 'funcdata_op.cc', 'unionresolve.cc',
  'pcodeinject.cc', 'heritage.cc', 'prefersplit.cc',
  'rangeutil.cc', 'ruleaction.cc', 'subflow.cc', 'blockaction.cc',
  'merge.cc', 'double.cc', 'coreaction.cc', 'condexe.cc', 'override.cc',
  'dynamic.cc', 'crc32.cc', 'prettyprint.cc', 'printlanguage.cc',
  'printc.cc', 'printjava.cc', 'memstate.cc', 'opbehavior.cc',
  'paramid.cc', 'transform.cc', 'string_ghidra.cc', 'constseq.cc',
  'ghidra_arch.cc', 'inject_ghidra.cc', 'ghidra_translate.cc',
  'loadimage_ghidra.cc', 'typegrp_ghidra.cc', 'database_ghidra.cc',
  'ghidra_context.cc', 'cpool_ghidra.cc', 'comment_ghidra.cc',
  'grammar.cc', 'xml.cc', 'pcodeparse.cc', 'libdecomp.cc',
  'sleigh_arch.cc', 'sleigh.cc', 'inject_sleigh.cc', 'pcodecompile.cc',
  'sleighbase.cc', 'slghsymbol.cc', 'slghpatexpress.cc', 'slghpattern.cc',
  'semantics.cc', 'context.cc', 'slaformat.cc', 'compression.cc',
  'filemanage.cc',
]

r2g_zlib_names = [
  'adler32.c', 'compress.c', 'crc32.c', 'deflate.c', 'gzclose.c',
  'gzlib.c', 'gzread.c', 'gzwrite.c', 'infback.c', 'inffast.c',
  'inflate.c', 'inftrees.c', 'trees.c', 'uncompr.c', 'zutil.c',
]

r2g_sources = []
foreach n : r2g_src_names
  r2g_sources += ['../src/' + n]
endforeach
foreach n : r2g_dec_names
  r2g_sources += ['../subprojects/ghidra-native/src/decompiler/' + n]
endforeach
foreach n : r2g_zlib_names
  r2g_sources += ['../subprojects/zlib/' + n]
endforeach

r2g_xps_lib = static_library('r2ghidra_xps',
  r2g_sources,
  include_directories: [
    include_directories(
      '../src',
      '../subprojects/ghidra-native/src/decompiler',
      '../subprojects/zlib'
    ),
    platform_inc,
  ],
  c_args: ['-DR2_PLUGIN_INCORE=1', '-DNDEBUG', '-fvisibility=hidden', '-w'],
  cpp_args: ['-DNDEBUG', '-fvisibility=hidden', '-w'],
  override_options: ['cpp_std=c++20', 'werror=false'],
  pic: true,
)

# XPS has no per-plugin dependency hook; platform_deps is consumed by
# libr_core's dependency list (and the other libr libraries, which pull
# nothing from this archive). link_with, not link_whole: libr_util links
# with --no-undefined and must not drag in objects needing r_core APIs.
# libr_core's static plugin table references r_core_plugin_r2ghidra, which
# pulls the whole chain out of the archive.
platform_deps += declare_dependency(link_with: r2g_xps_lib)
