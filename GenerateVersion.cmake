find_package(Git)

if(GIT_EXECUTABLE)
  get_filename_component(WORKING_DIR ${SRC} DIRECTORY)
  execute_process(
    COMMAND ${GIT_EXECUTABLE} describe --always --dirty
    WORKING_DIRECTORY ${WORKING_DIR}
    OUTPUT_VARIABLE PROGRAM_GIT_VERSION
    RESULT_VARIABLE ERROR_CODE
    OUTPUT_STRIP_TRAILING_WHITESPACE
    )

  if(NOT ERROR_CODE EQUAL "0")
    set(PROGRAM_GIT_VERSION "")
  endif()

endif()

if(PROGRAM_GIT_VERSION STREQUAL "")
  set(PROGRAM_GIT_VERSION 0.0.0-unknown)
  message(WARNING "Failed to determine version from Git tags. Using default version \"${PROGRAM_GIT_VERSION}\".")
else()
message("Git Version: \"${PROGRAM_GIT_VERSION}\".")
endif()

configure_file(${SRC} ${DST} @ONLY)