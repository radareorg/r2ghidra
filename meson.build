project(
  'r2ghidra',
  ['c', 'cpp'],
  license : 'LGPL3',
  meson_version : '>=0.50.1',
version : '6.0.8',
  default_options : ['c_std=c11', 'cpp_std=c++20']
)


r2ghidra_sources = [
  'src/R2Architecture.cpp',
  'src/R2LoadImage.cpp',
  'src/R2Scope.cpp',
  'src/R2TypeFactory.cpp',
  'src/R2CommentDatabase.cpp',
  'src/CodeXMLParse.cpp',
  'src/ArchMap.cpp',
  'src/R2PrintC.cpp',
  'src/RCoreMutex.cpp',
  'src/SleighAnalValue.cpp',
  'src/SleighAsm.cpp',
  'src/SleighInstruction.cpp',
  'src/PcodeFixupPreprocessor.cpp',
]

incdirs = [
  'src',
]

res = run_command(['radare2','-HR2_LIBR_PLUGINS'], capture:true, check:false)
if res.returncode() == 0
  r2_plugdir = res.stdout().strip()
else
  prefix = get_option('prefix')
  r2_plugdir = prefix + '/lib/radare2/plugins'
endif

cpp = meson.get_compiler('cpp')
if cpp.get_id() == 'msvc'
  incdirs += [
    'radare2/include/libr',
    'radare2/include/libr/sdb',
  ]
  add_global_arguments('-D_WINDOWS', language:'cpp')
  add_global_arguments('-D_WIN32', language:'cpp')
  add_global_arguments('-DZLIB_WINAPI', language:'cpp')
  add_global_arguments('-DR_ARENA_H=1', language:'cpp')
  add_global_arguments('/wd4200', language:'cpp')  # Suppress C4200: zero-sized array in struct
  r2libdir = [
    meson.current_source_dir() + '\\radare2\\lib',
    'C:\\radare2\\lib'
  ]
  r_core = [
    cpp.find_library('r_core', dirs: r2libdir),
    cpp.find_library('r_io', dirs: r2libdir),
    cpp.find_library('r_bin', dirs: r2libdir),
    cpp.find_library('r_cons', dirs: r2libdir),
    cpp.find_library('r_asm', dirs: r2libdir),
    cpp.find_library('r_esil', dirs: r2libdir),
    cpp.find_library('r_arch', dirs: r2libdir),
    cpp.find_library('r_flag', dirs: r2libdir),
    cpp.find_library('r_reg', dirs: r2libdir),
    cpp.find_library('r_util', dirs: r2libdir),
    cpp.find_library('r_anal', dirs: r2libdir),
    cpp.find_library('r_config', dirs: r2libdir),
  ]
else
  r_core = dependency('r_core')
endif

r2ghidra_version = meson.project_version()
versionconf = configuration_data()
versionconf.set('R2GHIDRA_VERSION', r2ghidra_version)
r_version_h = configure_file(
  input: 'config.h.acr',
  output: 'config.h',
  configuration: versionconf
)

add_global_arguments('-DNDEBUG', language: ['c', 'cpp'])

r2ghidra_incdirs = include_directories(incdirs)

zlib = dependency('zlib', version : '>=1.2.8', required: false)
if not zlib.found()
  zlib_proj = subproject('zlib', default_options: ['default_library=static', 'werror=false'])
  zlib = zlib_proj.get_variable('zlib_dep')
  meson.override_dependency('zlib', zlib)
endif


ghidra = subproject('ghidra-native', default_options: ['default_library=static', 'werror=false'])
# ghidra_decompiler_sources = ghidra.get_variable('sources')
# ghidra_slgh_sources = ghidra.get_variable('slgh_sources')
ghidra_incs = ghidra.get_variable('incs')
libdecomp_static = ghidra.get_variable('libdecomp_static')
slgh_static = ghidra.get_variable('slgh_static')

pugixml = subproject('pugixml').get_variable('pugixml_dep')

r2ghidra_core_sources = [
  r2ghidra_sources,
  # ghidra_decompiler_sources,
  'src/anal_ghidra_plugin.c',
  'src/anal_ghidra.cpp',
  'src/core_ghidra_plugin.c',
  'src/core_ghidra.cpp',
]

sleighc_sources = [
  r2ghidra_sources,
  # ghidra_slgh_sources,
  # ghidra_decompiler_sources,
]

r2ghidra_core_plugin = shared_library('core_r2ghidra',
  r2ghidra_core_sources,
  link_with: libdecomp_static,
  dependencies: [r_core, zlib, pugixml],
  override_options : ['c_std=c11', 'cpp_std=c++20'],
  include_directories: [ghidra_incs, r2ghidra_incdirs],
  install: true,
  install_dir: r2_plugdir
)

sleighc_exe = ghidra.get_variable('sleighc_exe')
subdir('ghidra')
