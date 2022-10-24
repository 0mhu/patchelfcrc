#ifndef _CRC_OUTPUT_STRUCT_H_
#define _CRC_OUTPUT_STRUCT_H_

#include <stdint.h>

/**
 * @brief Expected size of @ref crc_out_struct_32bit.
 * @note If the size of the structure does not match this number, structure padding occured which should not happen.
 */
#define CRC_OUT_STRUCT_SIZE_32BIT 12u

/**
 * @brief output structure of CRCs in a 32bit executable
*/
struct crc_out_struct_32bit {
	uint32_t start_address;	/**< @brief Start address of struct*/
	uint32_t length; 	/**< @brief Length of section in bytes */
	uint32_t crc;		/**< @brief LSB aligned CRC */
};

/**
 * @brief Expected size of @ref crc_out_struct_64bit.
 * @note If the size of the structure does not match this number, structure padding occured which should not happen.
 */
#define CRC_OUT_STRUCT_SIZE_64BIT 24u

/**
 * @brief output structure of CRCs in a 64bit executable
 */
struct crc_out_struct_64bit {
	uint64_t start_address;	/**< @brief Start address of struct*/
	uint64_t length; 	/**< @brief Length of section in bytes */
	uint32_t crc;		/**< @brief LSB aligned CRC */
    uint32_t _unused_dummy;	/**< @brief Dummy. Do not use, it prevents misalignments */
};

/**
 * @brief Trigger compile error if condition is false
 */
#define BUILD_ASSERT(cond) ((void)sizeof(char[1 - 2 * !!(cond)]))

/**
 * @brief Statically check sizes of @ref crc_out_struct_32bit and @ref crc_out_struct_64bit
 * @note Place this at least once in your code to ensure the packing of the structures is correct
 */
#define CRC_OUT_CHECK_STRUCT_SIZES do { \
	BUILD_ASSERT(sizeof(struct crc_out_struct_64bit) != CRC_OUT_STRUCT_SIZE_64BIT); \
	BUILD_ASSERT(sizeof(struct crc_out_struct_32bit) != CRC_OUT_STRUCT_SIZE_32BIT); \
} while(0)


#endif /* _CRC_OUTPUT_STRUCT_H_ */
