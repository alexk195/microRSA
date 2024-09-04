//
// Created by micro on 01.09.2024.
//

#ifndef RSA_TEST_H
#define RSA_TEST_H

#include <iomanip>

#include "qqq_rsa.h"

#define RSA_BYTES (2048/8)

/**
 * Generate sample data for 2048 bit
 * >openssl genrsa -out rsa2048.pem 2048
 * Make sure it says "e is 65537"
 * Dump modulus and copy to code modulus_s:
 * >openssl rsa -in rsa2048.pem -noout -modulus
 * Fill some clear text message
 * >echo "Hello RSA Encryption 2048 bit" >  clear_text.bin
 * Encrypt, but actually use decrypt param so we can use smaller input file and it matches the implementation
 * >openssl rsautl -raw -decrypt -inkey rsa2048.pem -in clear_text.bin -out encrypted.bin
 * Copy tne encrypted.bin to code enc_msg_s
 * >xxd -p encrypted.bin
 **/

//RSA512
#if RSA_BYTES == 64
const char* modulus_s=    "CBD885C939F6845BD925136F28915E0527E1AAF08BF6AB6B1AA81BE9AE9999B5A4232EDDAD717E31DF17FB29132303EB0CEC960799086C39CE634E8CFA04E6C3";
const char* enc_msg_s =   "b2482f2731750a619c03b65fc79a244eca7c269300f989e2e02f9751f9eeddbd0d67acb271c0c07e4366d314e2d9ae5be0bcab3e69f34b35f74bd2b340121e6f";
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

//note: strings commented out as it does not fit in memory...
//const char* crypt_s= "4906b7ee0adf855649f851d7008788a8afabb9ccc445ef71a5847c7f98b57982533ca2529116dc4a6f596750f14a2c4a200a1b4a6b07852ee95324a1d1413d45";
//const char* crypt_s =        "3e16898fb408b32d8d3380da146b9e113f8b3acb5cad3e0fb51da727dce5f8d490bbb56caf49a2120e92b0370a818f97c1b47667c0556c16f84139931bc39396";
//const char* pkcs_s= ""; //"54DBCFFA88C301182644E30E5B91926675FC23D93DB6968A1253968665210A3815B4E07E32A612C9D5691C594DC81045133FCB7F5919337D74AD89B5986026010E8EB583964ECB8101503EDAB36BC34772E6ABE56A69D4FBA29C71A0A94FFA79C7FA3283FF06BEFD81B35A7EE5D447A587D619F3B0BAE849027D975FE0234F72";
//const char* enc_msg_s =      "4906b7ee0adf855649f851d7008788a8afabb9ccc445ef71a5847c7f98b57982533ca2529116dc4a6f596750f14a2c4a200a1b4a6b07852ee95324a1d1413d45";

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

void test512() {
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

#endif //RSA_TEST_H
