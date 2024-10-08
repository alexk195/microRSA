#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "qqq_rsa.h"

//============================================
//bignum8 header
typedef struct _bignum8 {
  int length;
  int capacity;
  uint8_t* data;
} bignum8;

bignum8* bignum8_init(int capacity);
void bignum8_free(bignum8* b);
void bignum8_copy(bignum8* source, bignum8* dest);
void bignum8_multiply(bignum8* result, bignum8* a, bignum8* b);
int bignum8_bitlen(bignum8* v);
void bignum8_imodulate(bignum8* v, bignum8* n);
void bignum8_setlength(bignum8* b, int len, bool nozero=false);
uint32_t bignum8_getminlen(bignum8* v);
bignum8* bignum8_encode(bignum8* m, bignum8* n, uint8_t rounds);
bignum8* bignum8_frombin(uint8_t* bin, int len);
void bignum8_copy_same_capacity(bignum8* source, bignum8* dest);
//============================================

bignum8* bignum8_init(int capacity) {
  bignum8* b = (bignum8*)malloc(sizeof(bignum8));
  b->length = 0;
  b->capacity = capacity;
  b->data = (uint8_t*)calloc(capacity, sizeof(uint8_t));
  return b;
}

void bignum8_free(bignum8* b) {
  free(b->data);
  free(b);
}

//copy value with adjusting capacity
void bignum8_copy(bignum8* source, bignum8* dest) {
  int minlen = bignum8_getminlen(source);
  bignum8_setlength(dest, minlen, true);
  dest->length = minlen;
  memcpy(dest->data, source->data, minlen);
}

void bignum8_copy_same_capacity(bignum8* source, bignum8* dest) {
  dest->length = source->length;
  memcpy(dest->data, source->data, source->length);
}

void bignum8_multiply(bignum8* result, bignum8* a, bignum8* b) {
  // Allocate and zero memory for the result
  bignum8_setlength(result, a->length + b->length, true);
  memset(result->data, 0, result->length);

  // Use nested loops to multiply each digit of a with each digit of b
  uint32_t product;
  uint32_t carry;
  uint8_t *pa = a->data;
  uint8_t *pb = b->data;
  uint8_t *pr = result->data;
  for(int i = 0; i < a->length; i++) {
    carry = 0;
    pa = a->data+i;
    pb = b->data;
    pr = result->data+i;
    for(int j = 0; j < b->length; j++) {
      product = (uint32_t)(*pa) * (*pb) + (*pr) + carry;
      *pr = (uint8_t)(product & 0xFF);
      carry = product >> 8;
      pb++;
      pr++;
    }
    result->data[i + b->length] = (uint8_t)carry;
  }
}


//#####################################################

//shift right 1 bit
void shift_r1(unsigned char *a, int len) {
  if(a[0]&1)
    return;
  for(int i=0;i<len-1;i++) a[i]= (a[i]>>1) | ((a[i+1]&0x01)<<7);
  a[len-1]= (a[len-1]>>1);
}

//shift left 1 bit
void shift_l1(unsigned char *a, int len) {
  for(int i=len-1;i>0;i--) a[i]= (a[i]<<1) | ((a[i-1]&0x80)>>7);
  a[0]= (a[0]<<1);
}

//shift left 8 bits
void shift_l8(unsigned char *a, int len){
  for(int i=len-1;i>0;i--) a[i]=a[i-1];
  a[0]=0;
}

//get minimum length to hold number (left trim zeroes)
uint32_t bignum8_getminlen(bignum8* v){
  return (uint32_t)((bignum8_bitlen(v)+7)/8);
}

//count number of bits
int bignum8_bitlen(bignum8* v){
  for(int i=v->length-1;i>=0;i--) {
    if(v->data[i]!=0) {
      int bit = 7;
      uint8_t mask = 1<<bit;
      while(mask) {
        if(v->data[i]&mask) return i*8+bit+1;
        mask >>= 1;
        bit--;
      }
    }
  }
  return 0;
}

void bignum8_imodulate(bignum8* v, bignum8* n){
  int vlen = bignum8_bitlen(v);
  int nlen = bignum8_bitlen(n);
  int shift = vlen-nlen; //v is this many bits shifted from n
  if(shift<0) return; //v<n -> all done

  //make sure one byte additional is available for shifting/subtracting/adding
  bignum8_setlength(n, (nlen+7)/8+1);
  bignum8_setlength(v, (vlen+7)/8+1);

  //shift n into bit position
  for(int i=0;i<shift%8;i++) {
    shift_l1(n->data,n->length);
  }

  while(shift>=0) {
    int byteshift = shift / 8;

    //subtract shifted n from v
    uint16_t carry = 0;
    for(int i=0;i<n->length;i++) {
      carry += v->data[byteshift+i];
      carry -= n->data[i];
      v->data[byteshift+i] = (uint8_t)(carry & 0xff);
      if(carry&0x100) carry=0xffff; else carry=0;
    }

    if(carry!=0) {
      //too much subtracted -> restore v by adding shifted n to v
      carry=0;
      for(int i=0;i<n->length;i++) {
        carry += v->data[byteshift+i];
        carry += n->data[i];
        v->data[byteshift+i] = (uint8_t)(carry & 0xff);
        if(carry&0x100) carry=1; else carry=0;
      }
    }

    shift--;
    if(shift>=0) {
      if((shift%8)==7) shift_l8(n->data,n->length);
      shift_r1(n->data,n->length);
    }
  }

  //set length
  v->length = bignum8_bitlen(v)/8+1;
  n->length = bignum8_bitlen(n)/8+1;
}

//adjust length
void bignum8_setlength(bignum8* b, int len, bool nozero) {
  if(b->capacity < len) {
//    Serial.print("setlength() WITH realloc from ");
//    Serial.print(b->capacity);
//    Serial.print(" to ");
//    Serial.println(len);
    b->capacity = len;
    b->data = (uint8_t*)realloc(b->data, b->capacity);
  }else{
//    Serial.println("setlength() NO realloc\n");
  }
  if(!nozero)
    for(int i=b->length; i<len; i++)
      b->data[i]=0; //zero the new bytes
  b->length = len;
}


bignum8* bignum8_encode(bignum8* m, bignum8* n, uint8_t rounds) {
  bignum8 *v2 = bignum8_init(2*n->capacity);
  bignum8 *v = bignum8_init(2*n->capacity);

  bignum8_multiply(v2,m,m); //v2=m^2
  bignum8_imodulate(v2, n);
  bignum8_copy_same_capacity(v2,v); //v=m^2

  for(uint8_t i=0;i<rounds-1;i++) {
    bignum8_multiply(v2,v,v); //v2=v^2
    bignum8_imodulate(v2, n);
    bignum8_copy_same_capacity(v2,v); //v=v^2
  }

  bignum8_multiply(v2, m, v); //v2=m^3
  bignum8_imodulate(v2, n);
  bignum8_free(v);
  return v2;
}

//reverse bin
bignum8* bignum8_frombin(uint8_t* bin, int len) {
  bignum8* v = bignum8_init(len+1); //alloc 1 byte extra to prevent reallocs when doing operations
  v->length = len;
  for(int i = len-1; i>=0; i--) v->data[i] = bin[len-1-i];
  return v;
}

//returns 1 on success, 0 on failure
uint8_t bignum8_tobin(bignum8* v, uint8_t* bin, uint32_t len) {
  uint8_t minlen = bignum8_getminlen(v);
  if(minlen>len) return RSA_BUFFER_TO_SMALL_FOR_BIGNUM;
  memset(bin, 0, len);
  for(int i = minlen-1; i>=0; i--) bin[minlen-1-i] = v->data[i]; 
  return RSA_OK;
}

uint8_t rsa_encrypt_raw(uint8_t* modulus, uint8_t* msg_enc, uint8_t rounds, uint32_t rsa_bytes) {
  uint8_t retval;
  //check msg < modulus
  if(msg_enc[0] >= modulus[0]) return RSA_DATA_TOO_LARGE_FOR_MODULUS;

  //load modulus
  bignum8 *n8 = bignum8_frombin(modulus, rsa_bytes);

  bignum8 *m8 = bignum8_frombin(msg_enc, rsa_bytes);

  //compute crypt
  bignum8 *c8 = bignum8_encode(m8,n8, rounds);

  //store result
  retval = bignum8_tobin(c8, msg_enc, rsa_bytes);

  bignum8_free(c8);
  bignum8_free(m8);
  bignum8_free(n8);

  return retval;
}

uint8_t rsa_encrypt_pkcs(uint8_t* modulus, uint8_t* msg, uint8_t msglen, uint8_t* rnd_enc, uint8_t rounds, uint32_t rsa_bytes) {
  if(msglen>rsa_bytes-11) return RSA_DATA_TOO_LARGE_FOR_PADDING;

  //PKCS#1 v1.5 padding: 0x00 0x02 {random bytes != 0x00} 0x00 {msg[msglen]}
  //msg and rnd_enc are MSB first
  for(uint8_t i=0; i<msglen; i++) {
    rnd_enc[rsa_bytes-1-i] = msg[msglen-1-i];
  }
  rnd_enc[rsa_bytes-1-msglen]=0x00;
  for(uint8_t i=(uint8_t)(rsa_bytes-1-msglen-1); i>1; i--)
    if(rnd_enc[i] == 0x00)
      rnd_enc[i] = i+1;
  rnd_enc[1] = 0x02;
  rnd_enc[0] = 0x00;
  
  return rsa_encrypt_raw(modulus, rnd_enc,rounds, rsa_bytes);
}
