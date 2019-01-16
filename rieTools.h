// (c) 2018-2019 Pttn (https://github.com/Pttn/rieTools)

#include <iostream>
#include <vector>
#include <array>
#include <random>
#include <sstream>
#include <iomanip>
#include <gmp.h>
#include <gmpxx.h>
#include <openssl/sha.h>
#include <openssl/ripemd.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/bn.h>

void error(std::string message);
uint8_t rand(uint8_t min, uint8_t max);
bool validHex(const std::string &str);
std::string v8ToHexStr(std::vector<uint8_t> v);
std::string binToHexStr(const void* p, uint32_t len);
std::vector<uint8_t> hexStrToV8(std::string str);
void hexStrToBin(std::string str, uint8_t* data);
std::string gmp58Tobtc58(const std::string gmp58Str);
std::string btc58Togmp58(const std::string btc58Str);
std::string v8ToB58Str(const std::vector<uint8_t> v8);
std::vector<uint8_t> b58StrToV8(std::string btc58Str);
std::string toUpper(std::string str);
std::string toLower(std::string STR);
std::vector<uint8_t> sha256(const uint8_t *data, uint32_t len);
std::vector<uint8_t> sha256sha256(const uint8_t *data, uint32_t len);
std::vector<uint8_t> ripem160(const uint8_t *data, uint32_t len);
std::string prvBinToWif(const std::vector<uint8_t> &prvBin);
std::vector<uint8_t> addrToScriptPubKey(std::vector<uint8_t> addr);
bool ecdsaPubGen(const std::vector<uint8_t> &prvBin, std::string &pubHexFull, std::string &pubHexCompressed);
uint32_t getCompact(uint32_t nCompact);
uint32_t invEnd32(uint32_t x);
uint32_t constellationCheck(mpz_class n, std::vector<uint64_t> offsets, uint32_t iters, bool verbose = false);
mpz_class blockHeaderDecode(std::string bhStr, bool verbose = false);
