cmake_minimum_required(VERSION 3.5)

project(patchelfcrc LANGUAGES C)

find_package(PkgConfig REQUIRED)
pkg_check_modules(ELF REQUIRED libelf)

set (CFILES
	main.c
)

add_executable(${PROJECT_NAME} ${CFILES})
target_link_libraries(${PROJECT_NAME} ${ELF_LIBRARIES})
target_link_directories(${PROJECT_NAME} PRIVATE ${ELF_LIBRARY_DIRS})
target_include_directories(${PROJECT_NAME} PRIVATE ${ELF_INCLUDE_DIRS})




