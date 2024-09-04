#ifndef _QQQ_RSA_H_
#define _QQQ_RSA_H_

#include <stdint.h>

#define RSA_OK 0
#define RSA_BUFFER_TO_SMALL_FOR_BIGNUM 1
#define RSA_DATA_TOO_LARGE_FOR_MODULUS 2
#define RSA_DATA_TOO_LARGE_FOR_PADDING 3

// RSA encrypt raw
// plain text msg_enc[64] to encrypted msg_enc[RSA_BYTES], using modulus[RSA_BYTES]. modulus[RSA_BYTES] is unchanged
// NOTE: msg_enc should not be larger than modulus - use the rsa_pkcs_encrypt for correct padding.
// Input to rsa_ functions is MSB first as in openssl, bignum8 stores numbers LSB first
uint8_t rsa_encrypt_raw(uint8_t* modulus, uint8_t* msg_enc, uint8_t rounds, uint8_t RSA_BYTES);

// RSA encrypt with PKCS#1 v1.5 padding
// encrypt plain text msg[msglen] and random bytes rnd_enc[RSA_BYTES] to encrypted rnd_enc[RSA_BYTES], using modulus[RSA_BYTES]. modulus[RSA_BYTES] and msg[msglen] are unchanged
// NOTE: maximum msglen is RSA_BYTES-11
uint8_t rsa_encrypt_pkcs(uint8_t* modulus, uint8_t* msg, uint8_t msglen, uint8_t* rnd_enc, uint8_t rounds, uint8_t RSA_BYTES);

#endif // _QQQ_RSA_H_
