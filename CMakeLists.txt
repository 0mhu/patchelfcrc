cmake_minimum_required(VERSION 3.5)

project(patchelfcrc LANGUAGES C)

if(NOT WIN32)
  string(ASCII 27 Esc)
  set(ColorReset "${Esc}[m")
  set(ColorBold  "${Esc}[1m")
  set(Red         "${Esc}[31m")
  set(Green       "${Esc}[32m")
  set(Yellow      "${Esc}[33m")
  set(Blue        "${Esc}[34m")
  set(Magenta     "${Esc}[35m")
  set(Cyan        "${Esc}[36m")
  set(White       "${Esc}[37m")
  set(BoldRed     "${Esc}[1;31m")
  set(BoldGreen   "${Esc}[1;32m")
  set(BoldYellow  "${Esc}[1;33m")
  set(BoldBlue    "${Esc}[1;34m")
  set(BoldMagenta "${Esc}[1;35m")
  set(BoldCyan    "${Esc}[1;36m")
  set(BoldWhite   "${Esc}[1;37m")
endif()

find_package(PkgConfig REQUIRED)
pkg_check_modules(ELF REQUIRED libelf)

find_package(Doxygen)
find_package(LibXml2 REQUIRED)

add_subdirectory(man)

aux_source_directory("src" CFILES)

set(GEN_HEADER_PATH "${CMAKE_CURRENT_BINARY_DIR}/include/generated")

add_custom_target(
		version-header
	COMMAND
		mkdir -p ${GEN_HEADER_PATH} && bash "${CMAKE_CURRENT_SOURCE_DIR}/gen_version_header.sh" "${GEN_HEADER_PATH}/version.h"
	WORKING_DIRECTORY
		${CMAKE_CURRENT_SOURCE_DIR}
	COMMENT "Generating version header"
	)

add_custom_target(schema-header DEPENDS "${GEN_HEADER_PATH}/schema-blob.h")
add_custom_command(
	OUTPUT "${GEN_HEADER_PATH}/schema-blob.h"
	COMMAND mkdir -p ${GEN_HEADER_PATH} && bash -c "xxd -i schema.xsd>${GEN_HEADER_PATH}/schema-blob.h"
	DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/resources/schema.xsd"
	WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/resources"
	COMMENT "Generating XML schema"
)

add_compile_options(-Wall -Wextra -Wold-style-declaration -Wuninitialized -Wmaybe-uninitialized -Wunused-parameter)

set(FORT_ENABLE_TESTING OFF CACHE INTERNAL "")
add_subdirectory(3rdparty/libfort)
add_subdirectory(linklist-lib)

include_directories(${LIBXML2_INCLUDE_DIRS})

add_executable(${PROJECT_NAME} ${CFILES})
target_link_libraries(${PROJECT_NAME} ${ELF_LIBRARIES} ${LIBXML2_LIBRARIES} fort linklist-lib)
target_link_directories(${PROJECT_NAME} PRIVATE ${ELF_LIBRARY_DIRS} ${LIBXML2_LIBRARY_DIRS})
target_include_directories(${PROJECT_NAME} PRIVATE ${ELF_INCLUDE_DIRS})
target_include_directories(${PROJECT_NAME} PRIVATE "${CMAKE_CURRENT_BINARY_DIR}/include")
target_include_directories(${PROJECT_NAME} PRIVATE "include")
add_dependencies(${PROJECT_NAME} version-header schema-header)

if (DOXYGEN_FOUND)
	set(DOXYFILE_SRC "${CMAKE_CURRENT_SOURCE_DIR}/doxygen/Doxyfile.in")
	set(DOXYFILE_DEST "${CMAKE_CURRENT_BINARY_DIR}/Doxyfile")
	configure_file(${DOXYFILE_SRC} ${DOXYFILE_DEST} @ONLY)
	add_custom_target(doxygen
		DEPENDS
			doxygen-version-header
		COMMAND
			${DOXYGEN_EXECUTABLE} ${DOXYFILE_DEST}
		WORKING_DIRECTORY
			${CMAKE_CURRENT_SOURCE_DIR}
	)

	add_custom_target(doxygen-version-header
		COMMAND
			bash ${CMAKE_CURRENT_SOURCE_DIR}/doxygen/gen-version-string.sh "${CMAKE_CURRENT_BINARY_DIR}/doxyversion.in"
		WORKING_DIRECTORY
			${CMAKE_CURRENT_SOURCE_DIR}
	)
else (DOXYGEN_FOUND)
	message("${BoldMagenta}Doxygen needs to be installed to generate the doxygen documentation${ColorReset}")
	message("${BoldMagenta}doxygen target will not be available${ColorReset}")
endif (DOXYGEN_FOUND)
