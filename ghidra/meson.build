# Sleigh compilation for processor definitions

proc_file = meson.current_source_dir() / '..' / 'ghidra-processors.txt.default'
proc_res = run_command('cat', proc_file, check: true)
proc_list = proc_res.stdout().strip().split('\n')

proc_dir = meson.current_source_dir() / '..' / 'subprojects' / 'ghidra-native' / 'src' / 'Processors'
sleigh_dir = r2_plugdir / 'r2ghidra_sleigh'
sleigh_compile = meson.current_source_dir() / 'sleigh_compile.py'

python = find_program('python3', 'python', required: true)

foreach proc : ['DATA'] + proc_list
  proc = proc.strip()
  if proc == '' or proc.startswith('#')
    continue
  endif

  custom_target('sleigh-' + proc,
    command: [python, sleigh_compile, sleighc_exe, proc_dir / proc, '@OUTPUT@'],
    output: 'sleigh-' + proc + '.stamp',
    build_by_default: true,
  )

  install_subdir(proc_dir / proc / 'data' / 'languages',
    install_dir: sleigh_dir,
    strip_directory: true,
  )
endforeach
