project('pugixml', 'cpp', meson_version : '>=0.60.0', version : '1.15')

pugixml_sources = [
  'src/pugixml.cpp',
]

incdirs = [
  'src',
]

pugixml_dep = declare_dependency(
    sources: pugixml_sources,
    include_directories: include_directories(incdirs),
)
