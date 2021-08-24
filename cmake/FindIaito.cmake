# requires IAITO_SOURCE_DIR
# sets IAITO_INCLUDE_DIRS and Iaito::Iaito


set(_module Iaito)


# Prefer IaitoConfig.cmake from Iaito installation if available.
# FindIaito.cmake can be fully removed once all Iaito release packages include IaitoConfig.
find_package(${_module} CONFIG QUIET)
if(${_module}_FOUND)
	return()
endif()

if(IAITO_SOURCE_DIR)
	find_path(Iaito_SOURCE_ROOT
			NAMES core/Iaito.h
			PATHS "${IAITO_SOURCE_DIR}"
			PATH_SUFFIXES src
			NO_DEFAULT_PATH)
else()
	set(Iaito_SOURCE_ROOT Iaito_SOURCE_ROOT-NOTFOUND)
endif()

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(Iaito
		REQUIRED_VARS Iaito_SOURCE_ROOT
		FAIL_MESSAGE "#######################################################
Could not find Iaito headers. Make sure IAITO_SOURCE_DIR is set to the root of the Iaito source repository.
#######################################################
")

if(Iaito_FOUND)
	set(IAITO_INCLUDE_DIRS "${Iaito_SOURCE_ROOT}" "${Iaito_SOURCE_ROOT}/common" "${Iaito_SOURCE_ROOT}/core")
	add_library(${_module}::Iaito INTERFACE IMPORTED GLOBAL)
	target_include_directories(${_module}::Iaito INTERFACE ${IAITO_INCLUDE_DIRS})
endif()
