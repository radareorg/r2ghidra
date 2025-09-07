project('pugixml', 'cpp', meson_version : '>=0.60.0', version : '0e3f1699ffab5f820060fe99c61f0f9495c0c5b6')

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
