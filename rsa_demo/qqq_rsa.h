#ifndef _QQQ_RSA_H_
#define _QQQ_RSA_H_

#include <stdint.h>

#define RSA_OK 0
#define RSA_BUFFER_TO_SMALL_FOR_BIGNUM 1
#define RSA_DATA_TOO_LARGE_FOR_MODULUS 2
#define RSA_DATA_TOO_LARGE_FOR_PADDING 3

// RSA encrypt raw
// plain text msg_enc[64] to encrypted msg_enc[rsa_bytes], using modulus[rsa_bytes]. modulus[rsa_bytes] is unchanged
// NOTE: msg_enc should not be larger than modulus - use the rsa_pkcs_encrypt for correct padding.
// Input to rsa_ functions is MSB first as in openssl, bignum8 stores numbers LSB first
// returns RSA_OK or other error code
uint8_t rsa_encrypt_raw(uint8_t* modulus, uint8_t* msg_enc, uint8_t rounds, uint32_t rsa_bytes);

// RSA encrypt with PKCS#1 v1.5 padding
// encrypt plain text msg[msglen] and random bytes rnd_enc[rsa_bytes] to encrypted rnd_enc[rsa_bytes], using modulus[rsa_bytes]. modulus[rsa_bytes] and msg[msglen] are unchanged
// NOTE: maximum msglen is rsa_bytes-11
// returns RSA_OK or other error code
uint8_t rsa_encrypt_pkcs(uint8_t* modulus, uint8_t* msg, uint8_t msglen, uint8_t* rnd_enc, uint8_t rounds, uint32_t rsa_bytes);

#endif // _QQQ_RSA_H_
