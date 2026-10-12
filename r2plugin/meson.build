# r2ghidra XPS integration for radare2.
# Included from libr/xps/p/meson.build when the r2ghidra repository lives
# under libr/xps/p/r2ghidra/. Compiles the ghidra-native decompiler and the
# r2ghidra core plugin into a static helper library and appends its objects
# to the r_core aggregate so the plugin is linked into libr_core.

core_plugins += ['r2ghidra']

add_languages('cpp', native: false)

r2g_prep = run_command('make', '-C', meson.current_source_dir(), 'prepare', check: false)
if r2g_prep.returncode() != 0
  error('r2ghidra: prepare failed, run `make -C ' + meson.current_source_dir() + ' prepare` manually:\n' + r2g_prep.stderr())
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

r2g_python = find_program('python3', 'python', required: true)
r2g_source_reader = files('../subprojects/ghidra-native/scripts/sources.py')
import('fs').read('../subprojects/ghidra-native/sources.mk')
r2g_dec_names = run_command(r2g_python, r2g_source_reader, 'GHIDRA_EMBEDDED_SRCS', check: true).stdout().strip().split()

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
