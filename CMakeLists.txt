cmake_minimum_required(VERSION 3.0)
set(PKG_CONFIG_USE_CMAKE_PREFIX_PATH True)

project(r2ghidra)

set(RADARE2_INSTALL_PLUGDIR "lib/radare2/last" CACHE STRING "Directory to install radare2 plugin into")
set(CUTTER_INSTALL_PLUGDIR "share/RadareOrg/Cutter/plugins/native" CACHE STRING "Directory to install Cutter plugin into")

set(CUTTER_SOURCE_DIR CUTTER_SOURCE_DIR-NOTFOUND CACHE STRING "Root directory of Cutter source")

option(BUILD_CUTTER_PLUGIN "Build r2ghidra plugin for Cutter" OFF)
option(BUILD_DECOMPILE_EXECUTABLE "Build \"decompile\" executable as used by Ghidra (not needed for r2)" OFF)
option(BUILD_DECOMPILE_CLI_EXECUTABLE "Build REPL decompiler (not needed for r2)" OFF)
option(BUILD_SLASPECS "Build Sleigh specs for architectures from Ghidra" ON)
option(BUILD_SLEIGH_PLUGIN "Build asm and anal plugin to use sleigh as a disassembler in r2" ON)
option(GENERATE_PARSERS "Re-generate all parsers with Bison/Flex instead of using pre-generated ones" OFF)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

# C++latest needed for designed initializers, but funnily MSVC includes fail to compile with this flag
# if (MSVC_VERSION GREATER_EQUAL "1900")
# 	include(CheckCXXCompilerFlag)
# 	CHECK_CXX_COMPILER_FLAG("/std:c++latest" _cpp_latest_flag_supported)
# 	if (_cpp_latest_flag_supported)
# 		add_compile_options("/std:c++latest")
# 	endif()
# endif()

if(CMAKE_VERSION VERSION_LESS "3.1")
	if (CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
		add_definitions(-std=c++11)
	endif()
else()
	set(CMAKE_CXX_STANDARD 11)
endif()

if (MSVC_VERSION GREATER_EQUAL "1900")
	add_definitions(-D_WINDOWS)
	add_compile_options("/MT")
	set(CMAKE_CXX_FLAGS_RELEASE "/MT")
	set(CMAKE_CXX_FLAGS_DEBUG "/MTd")
endif()

add_subdirectory(ghidra)
add_subdirectory(third-party)

set(CORE_SOURCE
		src/core_ghidra.cpp
		src/R2Architecture.cpp
		src/R2Architecture.h
		src/R2LoadImage.cpp
		src/R2LoadImage.h
		src/R2Scope.cpp
		src/R2Scope.h
		src/R2TypeFactory.cpp
		src/R2TypeFactory.h
		src/R2CommentDatabase.cpp
		src/R2CommentDatabase.h
		src/CodeXMLParse.h
		src/CodeXMLParse.cpp
		src/ArchMap.h
		src/ArchMap.cpp
		src/R2PrintC.h
		src/R2PrintC.cpp
		src/RCoreMutex.h
		src/RCoreMutex.cpp
		src/r2ghidra.h)

if(BUILD_SLEIGH_PLUGIN)
set(ASM_SOURCE
		src/SleighAsm.h
		src/SleighAsm.cpp
		src/SleighInstruction.h
		src/SleighInstruction.cpp
		src/asm_ghidra.cpp
		src/ArchMap.h
		src/ArchMap.cpp)

set(ANAL_SOURCE
		src/SleighAsm.h
		src/SleighAsm.cpp
		src/SleighInstruction.h
		src/SleighInstruction.cpp
		src/SleighAnalValue.h
		src/SleighAnalValue.cpp
		src/anal_ghidra.cpp
		src/ArchMap.h
		src/ArchMap.cpp)
endif()

find_package(Radare2 REQUIRED)

add_library(core_ghidra SHARED ${CORE_SOURCE})
target_link_libraries(core_ghidra ghidra_decompiler_base ghidra_libdecomp ghidra_decompiler_sleigh)
target_link_libraries(core_ghidra pugixml)
target_link_libraries(core_ghidra Radare2::libr)
if (WIN32)
    target_link_libraries(core_ghidra Ws2_32.lib wininet)
endif()

set_target_properties(core_ghidra PROPERTIES
		OUTPUT_NAME core_ghidra
		PREFIX "")


if(BUILD_CUTTER_PLUGIN)
	add_subdirectory(cutter-plugin)
endif()


if (${CMAKE_SYSTEM_NAME} MATCHES "Darwin")
	string (REPLACE ";" " " LD_RPATH_STR "@loader_path")
else()
	string (REPLACE ";" " " LD_RPATH_STR "$ORIGIN")
endif()

if(BUILD_SLEIGH_PLUGIN)
add_library(asm_ghidra SHARED ${ASM_SOURCE})
target_link_libraries(asm_ghidra core_ghidra)
set_target_properties(asm_ghidra PROPERTIES
		OUTPUT_NAME asm_ghidra
		BUILD_RPATH "${LD_RPATH_STR}"
		INSTALL_RPATH "${LD_RPATH_STR}"
		PREFIX "")

add_library(anal_ghidra SHARED ${ANAL_SOURCE})
target_link_libraries(anal_ghidra core_ghidra)
set_target_properties(anal_ghidra PROPERTIES
		OUTPUT_NAME anal_ghidra
		BUILD_RPATH "${LD_RPATH_STR}"
		INSTALL_RPATH "${LD_RPATH_STR}"
		PREFIX "")
endif()

if(SLEIGHHOME_DEFAULT)
	target_compile_definitions(core_ghidra PRIVATE "-DR2GHIDRA_SLEIGHHOME_DEFAULT=\"${SLEIGHHOME_DEFAULT}\"")
	if(BUILD_SLEIGH_PLUGIN)
	target_compile_definitions(asm_ghidra PRIVATE "-DR2GHIDRA_SLEIGHHOME_DEFAULT=\"${SLEIGHHOME_DEFAULT}\"")
	target_compile_definitions(anal_ghidra PRIVATE "-DR2GHIDRA_SLEIGHHOME_DEFAULT=\"${SLEIGHHOME_DEFAULT}\"")
	endif()
endif()

install(TARGETS core_ghidra DESTINATION "${RADARE2_INSTALL_PLUGDIR}")
if(BUILD_SLEIGH_PLUGIN)
install(TARGETS asm_ghidra DESTINATION "${RADARE2_INSTALL_PLUGDIR}")
install(TARGETS anal_ghidra DESTINATION "${RADARE2_INSTALL_PLUGDIR}")
endif()
