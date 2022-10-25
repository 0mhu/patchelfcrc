set (MAN_PAGE_NAME "patchelfcrc.1.gz")

add_custom_target(man-page
	ALL
	DEPENDS
		${CMAKE_CURRENT_BINARY_DIR}/${MAN_PAGE_NAME}
)

add_custom_command(
	OUTPUT
		${CMAKE_CURRENT_BINARY_DIR}/${MAN_PAGE_NAME}
	COMMAND
		bash -c "pandoc \"${CMAKE_CURRENT_SOURCE_DIR}/patchelfcrc.1.md\" -s -t man | gzip > \"${CMAKE_CURRENT_BINARY_DIR}/${MAN_PAGE_NAME}\""
	VERBATIM
	WORKING_DIRECTORY
		${CMAKE_CURRENT_BINARY_DIR}
	MAIN_DEPENDENCY
		${CMAKE_CURRENT_SOURCE_DIR}/patchelfcrc.1.md
)