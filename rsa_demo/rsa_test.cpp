//
// Created by micro on 01.09.2024.
//



#ifdef ARDUINO
#include <Arduino.h>
#else
#include <iostream>
#include <chrono>
#endif
#include <iomanip>

#include "qqq_rsa.h"

// use 512/8 or 1024/8 or 2048/8
#define RSA_BYTES (1024/8)

/**
 * Performance on SAMD21 for raw encrypt:
 *        RSA512/rounds=16 => 783ms
 *        RSA1024/rounds=1 => 365ms
 *        RSA2048/rounds=16 => 12s
 *
 * Generate sample data for 2048 bit (for 512 or 1024 accordingly)
 * >openssl genrsa -out rsa2048.pem 2048
 * Make sure it says "e is 65537". Then rounds=16, If you use -3 than "e is 3" and rounds=1
 * Dump modulus and copy to code modulus_s:
 * >openssl rsa -in rsa2048.pem -noout -modulus
 * Fill some clear text message
 * >echo "Hello RSA Encryption 2048 bit" >  clear_text.bin
 * Encrypt, but actually use decrypt param so we can use smaller input file, and it matches the implementation
 * >openssl rsautl -raw -decrypt -inkey rsa2048.pem -in clear_text.bin -out encrypted.bin
 * Copy tne encrypted.bin to code enc_msg_s
 * >xxd -p encrypted.bin
 * Faster execution with rounds=1, e=3:
 *  Use openssl genrsa -3 ...
 **/

//RSA512
#if RSA_BYTES == 64
const char* modulus_s=    "CAA0D3DA5F211A9C79487BEA2D07268254F7572225D602B5029DAE41CE3853ABB44B50430BC4D7B873E3A1577D315C84A2332F3AA23B70F3F1691BB0CBCF988D";
const char* enc_msg_s =   "554caffe87ac187d5680d3658289b466459475f9487c7c1cec7dbe76ea4f48132af43cd543bc9d49545136ab4fc7e919ecf088b3937ad776beb6fe69af8c86f1";
const uint8_t rounds = 16;
#endif

#if RSA_BYTES == 128
const char* modulus_s = "C80FAD66A8B4DFEC5BC7762460F45FE842F850BAC73501E5E57358F7E9B87082D2A0332B55C27E3467C2690F75561675FFCCA66DD52402A6BB247ADE00DE3B1D630782F47F142530B634AA3C06EDAE6B1C723C199897398780241B930278827AD595BAE37F3AAFC69843250AC92AF744780790B1804C40919F23725C9B09FB49";
const char* enc_msg_s = "6fca7f1de35e67e2117aae0856bd7243d307d981f228f42804ae9b6349cb5e9ddf189c1c432df89cea5971d8266a8f0e464ce795f76294dabf0d68ac0f740cdd3735a2df3f93a6251b478acabafe9f191da6a91728483e2d0f97305e71a488d25c9b5a293e0f3c459de39ad99137ab164c2f254a0e1d1de8e167658f3eb68167";
const uint8_t rounds = 1;
#endif

//RSA 2048
#if RSA_BYTES == 256
const char* modulus_s=  "C5034DFA9676B90C741609C7386BC86046BEB695853846E0CE5CCD4C67FE4FFBBF3BE0DB2BA3BAC0B880B015A545A3FB4DBED50648D73C395F517135E19BFD5027F5ADE19E77088419083068C63945BC2C2C77F5D8E43407AE49E622A5BD2E805F209C98169F94E5FA44FA73936431963FA8A18AA41E78CAEB1C4DCADBF757545AE179741A2F84A4B647AD0A2C26B21F1B0CAE981C9F83810336D3DBB3FFCF960895D2BD23421DFD6E25B96720A7457FD04EAFA718D23637FE430E36D0A24609084CB0C3EF8994421F1A6AA0ACE80CD9F5472DB40BCD7EA467A432D21BA8AD61AA8A676497DF6A1A191C656A3FB1AEACB011ED8902AE742D354DD572C59E1CF3";
const char* enc_msg_s = "3a480121b08561243b3bc5db565bbed719bb75a5503fc02497e996beb009"
                        "3e9704f5e95f1bffd6148c5e0ac60430850da25478ef6478b1a226dca96d"
                        "75022a389e7cd3d2113192c1194a8bd8e6197f8b698c17ed0b75eb4a5515"
                        "218ac937f942b8ea3e7142e78384ff086468f72066c13dfc047d34550f90"
                        "949d980b3c63ae32ab0a96498540d013c3ac62f343e86db8d1c7519f4cac"
                        "2796fefce35b9e5a3e4efe94935e00b0f49ee8fd8328c03da85f455ab320"
                        "8ffb928d309d0ae7e1aefda1b0487a36b13e0fb46e1b1cbafed3f1b8d875"
                        "4361a95046d2e8062037da7534f1ae6fb50d8c98c2b9a565c77447f7d5de"
                        "e2219d47ab085e07734890e07b52ba5e";

const uint8_t rounds = 16;
#endif

const char* msg_expected_s = enc_msg_s;

//convert hex string to binary, returns len
uint32_t hex2bin(const char* string, uint8_t *bin, uint32_t binlen) {
  int i=0;
  uint8_t b=0;
  int nibble = 0;
  uint32_t pos=0;
  while(string[i] != '\0' && pos < binlen) {
    char c = string[i];
    if(c>='0' && c<='9') {
      nibble++;
      b = uint8_t(b*0x10 + c - '0');
    }else if(c>='A' && c<='F'){
      nibble++;
      b = uint8_t(b*0x10 + c - 'A' + 10);
    }else if(c>='a' && c<='f'){
      nibble++;
      b = uint8_t(b*0x10 + c - 'a' + 10);
    }
    i++;
    if(nibble==2) {
      bin[pos++] = b;
      b=0;
      nibble=0;
    }
  }
  //trailing nibble
  if(nibble>0) bin[pos++] = b;
  return uint8_t(pos);
}

#ifdef ARDUINO
void printbin(const uint8_t* b, uint32_t len) {
  for (uint32_t i = 0; i < len; i++) {
    if (b[i] < 0x10) Serial.print("0");
    Serial.print(b[i], HEX);
  }
  Serial.print(" len=");
  Serial.println(len, DEC);
}
#else
void printbin(const uint8_t* b, uint32_t len) {
  for (uint32_t i = 0; i < len; i++) {
    if (b[i] < 0x10) std::cout << "0";
    std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(b[i]);
  }
  std::cout << " len=" << std::dec << static_cast<int>(len) << std::endl;
}
#endif


#ifdef ARDUINO
void printbinreverse(const uint8_t* b, uint8_t len) {
  for (int i = len - 1; i >= 0; i--) {
    if (b[i] < 0x10) Serial.print("0");
    Serial.print(b[i], HEX);
  }
  Serial.print(" len=");
  Serial.println(len, DEC);
}
#else
void printbinreverse(const uint8_t* b, uint8_t len) {
  for (int i = len - 1; i >= 0; i--) {
    if (b[i] < 0x10) std::cout << "0";
    std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(b[i]);
  }
  std::cout << " len=" << std::dec << static_cast<int>(len) << std::endl;
}
#endif

void create_msg(uint8_t *msg) {
  for(uint8_t i=0;i<RSA_BYTES;i++) msg[i] = i;
}

void println(const char * s) {
#ifdef ARDUINO
  Serial.println(s);
#else
  std::cout << s << std::endl;
#endif
}

void print(const char * s) {
#ifdef ARDUINO
  Serial.print(s);
#else
  std::cout << s;
#endif
}

void printInt(int i) {
#ifdef ARDUINO
  Serial.print(i);
#else
  std::cout << i;
#endif
}

void rsa_test() {
  uint8_t modulus[RSA_BYTES];
  uint8_t msg[RSA_BYTES];
  uint8_t msg_expected[RSA_BYTES];

  hex2bin(modulus_s, modulus, RSA_BYTES);
  print("\nmodulus= ");
  printbin(modulus, RSA_BYTES);

  hex2bin(enc_msg_s, msg, RSA_BYTES);

  print("\nmessage= ");
  printbin(msg, RSA_BYTES);


  hex2bin(msg_expected_s, msg_expected, RSA_BYTES);

  print("\n\nRAW ENCRYPT: ");
  #ifdef ARDUINO
  auto t1 = micros();
  #else
  auto t1 = std::chrono::high_resolution_clock::now();
  #endif

  uint8_t rv = rsa_encrypt_raw(modulus, msg, rounds, RSA_BYTES);
  #ifdef ARDUINO
  auto t2 = micros();
  auto duration = t2-t1;
  #else
  auto t2 = std::chrono::high_resolution_clock::now();
  auto duration = std::chrono::duration_cast<std::chrono::microseconds>(t2 - t1).count();
  #endif

  print("Duration [us]:");
  printInt((int)duration);

  print("\nretval=");
  print(rv == 0 ? "OK" : " ERROR");
  if (rv != 0) {
    printInt(rv);
  }

  print("\ndecrypted=");
  printbin(msg, RSA_BYTES);
  print("\nAscii:");
  println((const char*)msg);

  print("\nmsg_expected=");
  printbin(msg_expected, RSA_BYTES);
  println("");

  return;

  /*
  create_msg(msg);
  std::cout << "\n\nPKCS ENCRYPT: ";
  uint8_t rnd_enc[RSA_BYTES];
  memset(rnd_enc, 0xAA, RSA_BYTES);
  rv = rsa_encrypt_pkcs(modulus, msg, 5, rnd_enc);
  std::cout << "retval=" << (rv == 0 ? "OK" : " ERROR" + std::to_string(rv));

  std::cout << "\npkcs=    ";
  printbin(rnd_enc, RSA_BYTES);

  std::cout << "\nexpected=";
  std::cout << pkcs_s;
  std::cout << "\n\n";

   */
}
