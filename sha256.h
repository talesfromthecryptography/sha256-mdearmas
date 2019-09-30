
/*********************************************************************
* Filename:   sha256.h
* Author:
* Copyright:
* Disclaimer: This code is presented "as is" without any guarantees.
* Details:    Defines the API for the corresponding SHA1 implementation.
*********************************************************************/

#ifndef SHA256_H
#define SHA256_H

/*************************** HEADER FILES ***************************/

/****************************** MACROS ******************************/

#define SHA256_DIGEST_SIZE 256/32
#define SHA256_BUFFER_SIZE 512/32
#define NUM_ROUNDS 64
#define BUFFER_FULL 512/8

/****************************** TYPES ******************************/


typedef struct {
	uint32_t buffer[SHA256_BUFFER_SIZE]; // buffer input until we can transform 512 bits
	uint8_t  buffer_bytes_used;

	uint64_t bit_len;                 // used in final padding

	uint32_t digest[SHA256_DIGEST_SIZE];
} sha256_state;

/*********************** FUNCTION DECLARATIONS **********************/
void sha256_init(sha256_state *state);
void sha256_update(sha256_state *state, const uint8_t data[], int len);
void sha256_final(sha256_state *state,  uint8_t hash[]);

void buffer_print(sha256_state *state);

#endif   // SHA256_H
