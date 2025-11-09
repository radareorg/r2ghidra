fs = import('fs')
proc_file = meson.current_source_dir() / '..' / 'ghidra-processors.txt.default'
proc_list = fs.read(proc_file).strip().split('\n')

proc_dir = meson.current_source_dir() / '..' / 'subprojects' / 'ghidra-native' / 'src' / 'Processors'
sleigh_dir = r2_plugdir / 'r2ghidra_sleigh'

foreach proc : proc_list
  proc = proc.strip()
  if proc != '' and not proc.startswith('#')
    custom_target('sleigh-' + proc,
      command: [sleighc_exe, '-a', proc_dir / proc],
      output: proc + '.stamp',
    )

    lang_dir = proc_dir / proc / 'data' / 'languages'
    if fs.is_dir(lang_dir)
      install_subdir(lang_dir,
        install_dir: sleigh_dir,
        strip_directory: true,
        exclude_directories: ['*'],
      )
    endif
  endif
endforeach
