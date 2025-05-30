project(
  'r2ghidra',
  ['c', 'cpp'],
  license : 'LGPL3',
  meson_version : '>=0.50.1',
version : '5.9.8',
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

incdirs = [
  'src',
  'third-party/pugixml/src/',
  'ghidra-native/src/decompiler/',
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

r2ghidra_incdirs = include_directories(incdirs)

ghidra_decompiler_sources = [
  'ghidra-native/src/decompiler/action.cc',
  'ghidra-native/src/decompiler/address.cc',
  'ghidra-native/src/decompiler/architecture.cc',
  # 'ghidra-native/src/decompiler/bfd_arch.cc',
  'ghidra-native/src/decompiler/block.cc',
  'ghidra-native/src/decompiler/blockaction.cc',
  'ghidra-native/src/decompiler/callgraph.cc',
  'ghidra-native/src/decompiler/capability.cc',
  'ghidra-native/src/decompiler/cast.cc',
  # 'ghidra-native/src/decompiler/codedata.cc',
  'ghidra-native/src/decompiler/comment.cc',
  'ghidra-native/src/decompiler/comment_ghidra.cc',
  'ghidra-native/src/decompiler/condexe.cc',
  # 'ghidra-native/src/decompiler/consolemain.cc',
  'ghidra-native/src/decompiler/context.cc',
  'ghidra-native/src/decompiler/coreaction.cc',
  'ghidra-native/src/decompiler/cover.cc',
  'ghidra-native/src/decompiler/cpool.cc',
  'ghidra-native/src/decompiler/cpool_ghidra.cc',
  'ghidra-native/src/decompiler/crc32.cc',
  'ghidra-native/src/decompiler/database.cc',
  'ghidra-native/src/decompiler/database_ghidra.cc',
  'ghidra-native/src/decompiler/double.cc',
  'ghidra-native/src/decompiler/dynamic.cc',
  'ghidra-native/src/decompiler/emulate.cc',
  'ghidra-native/src/decompiler/emulateutil.cc',
  'ghidra-native/src/decompiler/filemanage.cc',
  'ghidra-native/src/decompiler/float.cc',
  'ghidra-native/src/decompiler/flow.cc',
  'ghidra-native/src/decompiler/fspec.cc',
  'ghidra-native/src/decompiler/multiprecision.cc',
  'ghidra-native/src/decompiler/funcdata.cc',
  'ghidra-native/src/decompiler/funcdata_block.cc',
  'ghidra-native/src/decompiler/funcdata_op.cc',
  'ghidra-native/src/decompiler/funcdata_varnode.cc',
  'ghidra-native/src/decompiler/unionresolve.cc',
  'ghidra-native/src/decompiler/ghidra_arch.cc',
  'ghidra-native/src/decompiler/ghidra_context.cc',
  # 'ghidra-native/src/decompiler/ghidra_process.cc',
  'ghidra-native/src/decompiler/ghidra_translate.cc',
  'ghidra-native/src/decompiler/globalcontext.cc',
  'ghidra-native/src/decompiler/grammar.cc',
  'ghidra-native/src/decompiler/graph.cc',
  'ghidra-native/src/decompiler/heritage.cc',
  'ghidra-native/src/decompiler/ifacedecomp.cc',
  'ghidra-native/src/decompiler/testfunction.cc',
  'ghidra-native/src/decompiler/ifaceterm.cc',
  'ghidra-native/src/decompiler/inject_ghidra.cc',
  'ghidra-native/src/decompiler/inject_sleigh.cc',
  'ghidra-native/src/decompiler/interface.cc',
  'ghidra-native/src/decompiler/jumptable.cc',
  'ghidra-native/src/decompiler/libdecomp.cc',
  'ghidra-native/src/decompiler/loadimage.cc',
  # 'ghidra-native/src/decompiler/loadimage_bfd.cc',
  'ghidra-native/src/decompiler/loadimage_ghidra.cc',
  'ghidra-native/src/decompiler/loadimage_xml.cc',
  'ghidra-native/src/decompiler/memstate.cc',
  'ghidra-native/src/decompiler/merge.cc',
  'ghidra-native/src/decompiler/op.cc',
  'ghidra-native/src/decompiler/opbehavior.cc',
  'ghidra-native/src/decompiler/opcodes.cc',
  'ghidra-native/src/decompiler/options.cc',
  'ghidra-native/src/decompiler/override.cc',
  'ghidra-native/src/decompiler/paramid.cc',
  'ghidra-native/src/decompiler/pcodecompile.cc',
  'ghidra-native/src/decompiler/pcodeinject.cc',
  'ghidra-native/src/decompiler/pcodeparse.cc',
  'ghidra-native/src/decompiler/pcoderaw.cc',
  'ghidra-native/src/decompiler/prefersplit.cc',
  'ghidra-native/src/decompiler/prettyprint.cc',
  'ghidra-native/src/decompiler/printc.cc',
  'ghidra-native/src/decompiler/printjava.cc',
  'ghidra-native/src/decompiler/printlanguage.cc',
  'ghidra-native/src/decompiler/rangeutil.cc',
  'ghidra-native/src/decompiler/raw_arch.cc',
  'ghidra-native/src/decompiler/ruleaction.cc',
  'ghidra-native/src/decompiler/rulecompile.cc',
  'ghidra-native/src/decompiler/compression.cc',
  'ghidra-native/src/decompiler/slaformat.cc',
  'ghidra-native/src/decompiler/semantics.cc',
  'ghidra-native/src/decompiler/sleigh.cc',
  'ghidra-native/src/decompiler/sleigh_arch.cc',
  'ghidra-native/src/decompiler/sleighbase.cc',
  # 'ghidra-native/src/decompiler/sleighexample.cc',
  # 'ghidra-native/src/decompiler/slgh_compile.cc',
  # 'ghidra-native/src/decompiler/slghparse.cc',
  'ghidra-native/src/decompiler/slghpatexpress.cc',
  'ghidra-native/src/decompiler/slghpattern.cc',
  # 'ghidra-native/src/decompiler/slghscan.cc',
  'ghidra-native/src/decompiler/slghsymbol.cc',
  'ghidra-native/src/decompiler/marshal.cc',
  'ghidra-native/src/decompiler/space.cc',
  'ghidra-native/src/decompiler/string_ghidra.cc',
  'ghidra-native/src/decompiler/stringmanage.cc',
  'ghidra-native/src/decompiler/modelrules.cc',
  'ghidra-native/src/decompiler/subflow.cc',
  'ghidra-native/src/decompiler/transform.cc',
  'ghidra-native/src/decompiler/translate.cc',
  'ghidra-native/src/decompiler/type.cc',
  'ghidra-native/src/decompiler/typegrp_ghidra.cc',
  'ghidra-native/src/decompiler/typeop.cc',
  'ghidra-native/src/decompiler/unify.cc',
  'ghidra-native/src/decompiler/userop.cc',
  'ghidra-native/src/decompiler/variable.cc',
  'ghidra-native/src/decompiler/varmap.cc',
  'ghidra-native/src/decompiler/varnode.cc',
  'ghidra-native/src/decompiler/xml.cc',
  'ghidra-native/src/decompiler/xml_arch.cc',
]

r2ghidra_core_sources = [
  r2ghidra_sources,
  pugixml_sources,
  ghidra_decompiler_sources,
  'src/anal_ghidra_plugin.c',
  'src/anal_ghidra.cpp',
  'src/core_ghidra_plugin.c',
  'src/core_ghidra.cpp'
]

sleighc_sources = [
  r2ghidra_sources,
  pugixml_sources,
  'ghidra-native/src/decompiler/slgh_compile.cc',
  'ghidra-native/src/decompiler/slghparse.cc',
  'ghidra-native/src/decompiler/slghscan.cc',
  ghidra_decompiler_sources,
]

r2ghidra_core_plugin = library('core_r2ghidra',
  r2ghidra_core_sources,
  dependencies: [r_core],
  override_options : ['c_std=c11', 'cpp_std=c++11'],
  include_directories: r2ghidra_incdirs,
  install: true,
  install_dir: r2_plugdir
)

sleighc_exe = executable('sleighc', sleighc_sources,
  include_directories: r2ghidra_incdirs,
  override_options : ['c_std=c11', 'cpp_std=c++11'],
  dependencies: [r_core],
  install: true
)
