//
// Created by micro on 01.09.2024.
//

#ifndef RSA_TEST_H
#define RSA_TEST_H

#include <iomanip>

#define RSA_BYTES (512/8)

#include "qqq_rsa.h"

//RSA512
const char* modulus_s=       "CBD885C939F6845BD925136F28915E0527E1AAF08BF6AB6B1AA81BE9AE9999B5A4232EDDAD717E31DF17FB29132303EB0CEC960799086C39CE634E8CFA04E6C3";

//note: strings commented out as it does not fit in memory...
//const char* crypt_s= "4906b7ee0adf855649f851d7008788a8afabb9ccc445ef71a5847c7f98b57982533ca2529116dc4a6f596750f14a2c4a200a1b4a6b07852ee95324a1d1413d45";
const char* crypt_s =        "3e16898fb408b32d8d3380da146b9e113f8b3acb5cad3e0fb51da727dce5f8d490bbb56caf49a2120e92b0370a818f97c1b47667c0556c16f84139931bc39396";
const char* pkcs_s= ""; //"54DBCFFA88C301182644E30E5B91926675FC23D93DB6968A1253968665210A3815B4E07E32A612C9D5691C594DC81045133FCB7F5919337D74AD89B5986026010E8EB583964ECB8101503EDAB36BC34772E6ABE56A69D4FBA29C71A0A94FFA79C7FA3283FF06BEFD81B35A7EE5D447A587D619F3B0BAE849027D975FE0234F72";
const char* enc_msg_s =      "4906b7ee0adf855649f851d7008788a8afabb9ccc445ef71a5847c7f98b57982533ca2529116dc4a6f596750f14a2c4a200a1b4a6b07852ee95324a1d1413d45";
const char* dec_msg_s =      "38787c1b965df0a867a34335553c053d7a2abb9692771aea7c8f7c6c5c7789a0b187004561ed1532aaac3c3d357b5e5939dd1a3cb668474ebec18ee2fc0b1328";
const char* msg_expected_s = "48656c6c6f2052534120456e6372797074696f6e210a000000000000000000000000000000000000000000000000000000000000000000000000000000000000";

//convert hex string to binary, returns len
uint8_t hex2bin(const char* string, uint8_t *bin, uint8_t binlen) {
  int i=0;
  uint8_t b=0;
  int nibble = 0;
  int pos=0;
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
void printbin(const uint8_t* b, uint8_t len) {
  for (int i = 0; i < len; i++) {
    if (b[i] < 0x10) Serial.print("0");
    Serial.print(b[i], HEX);
  }
  Serial.print(" len=");
  Serial.println(len, DEC);
}
#else
void printbin(const uint8_t* b, uint8_t len) {
  for (int i = 0; i < len; i++) {
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

  hex2bin(dec_msg_s, msg, RSA_BYTES);

  print("\nmessage= ");
  printbin(msg, RSA_BYTES);


  hex2bin(msg_expected_s, msg_expected, RSA_BYTES);

  print("\n\nRAW ENCRYPT: ");
  #ifdef ARDUINO
  auto t1 = micros();
  #else
  auto t1 = std::chrono::high_resolution_clock::now();
  #endif

  uint8_t rv = rsa_encrypt_raw(modulus, msg, 1, RSA_BYTES);
  #ifdef ARDUINO
  auto t2 = micros();
  auto duration = t2-t1;
  #else
  auto t2 = std::chrono::high_resolution_clock::now();
  auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(t2 - t1).count();
  #endif

  print("Duration:");
  printInt(t2-t1);

  print("\nretval=");
  print(rv == 0 ? "OK" : " ERROR");
  if (rv != 0) {
    printInt(rv);
  }

  print("\nencrypted=");
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
