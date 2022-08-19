cmake_minimum_required(VERSION 3.5)

project(patchelfcrc LANGUAGES C)

find_package(PkgConfig REQUIRED)
pkg_check_modules(ELF REQUIRED libelf)

set (CFILES
	main.c
	version.c
	named_crcs.c
)

set(GEN_HEADER_PATH "${CMAKE_CURRENT_BINARY_DIR}/include/generated")

add_custom_target(
		version-header
	COMMAND
		mkdir -p ${GEN_HEADER_PATH} && bash "${CMAKE_CURRENT_SOURCE_DIR}/gen_version_header.sh" "${GEN_HEADER_PATH}/version.h"
	WORKING_DIRECTORY
		${CMAKE_CURRENT_SOURCE_DIR}
	)

add_compile_options(-Wall -Wextra -Wold-style-declaration -Wuninitialized -Wmaybe-uninitialized -Wunused-parameter)

add_executable(${PROJECT_NAME} ${CFILES})
target_link_libraries(${PROJECT_NAME} ${ELF_LIBRARIES})
target_link_directories(${PROJECT_NAME} PRIVATE ${ELF_LIBRARY_DIRS})
target_include_directories(${PROJECT_NAME} PRIVATE ${ELF_INCLUDE_DIRS})
target_include_directories(${PROJECT_NAME} PRIVATE "${CMAKE_CURRENT_BINARY_DIR}/include")
target_include_directories(${PROJECT_NAME} PRIVATE "include")
add_dependencies(${PROJECT_NAME} version-header)


