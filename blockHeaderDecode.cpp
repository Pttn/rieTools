// (c) 2018 Pttn (https://github.com/Pttn/rieTools)
// Simple Riecoin Blockheader decoder, simply decomposes the block header and show if the numbers in the 6-tuple are prime
// The official FAQ may help: http://riecoin.org/faq.html

// Sample blockheaders:
// 00000020cc859e93e78e17234f8c7ffa51e67da737a26095237bac43f11dd1e3e7ece0888a4880aa5ddf42d9faaa713b7d370ce4c99ca2a894b65842a5c1716de4a51cd5004f0502a376f95b00000000f5aaaf9f81e899f0884f59429b85298daedcbe7204f91dfe7a307e50a4e97f27
// 020000007587e684cefb59a5f440e017a75ebe25bc3b6faf6c4cb7c9405c2879acd2b18e11932f89e9c9a35e46544a46381f771b51a67518595c2328de863bfb935f6e1900300102bd07fa5b000000008f8f4021ac38014d8d131f270c7b8fd216b89b75c23c05c272574e312e8bdd10

// Depends on GMP (with its C++ wrapper) and LibSsl (LibCrypto)
// Compile with 'g++ blockHeaderDecode.cpp -Os -o blockHeaderDecode -l gmp -l gmpxx -l crypto'
// Only tested on Linux (Debian 9)

#include <iostream>
#include <vector>
#include <array>
#include <iomanip>
#include <gmp.h>
#include <gmpxx.h>
#include <openssl/sha.h>

bool validHex(const std::string &str) {
	for (uint16_t i(0) ; i < str.size() ; i++) {
		if (!(str[i] >= '0' && str[i] <= '9'
		   || str[i] >= 'A' && str[i] <= 'F'
		   || str[i] >= 'a' && str[i] <= 'f'))
			return false;
	}
	return true;
}

std::string v8ToHexStr(std::vector<uint8_t> v) {
	std::ostringstream oss;
	for (uint32_t i(0) ; i < v.size() ; i++)
		oss << std::setfill('0') << std::setw(2) << std::hex << (uint32_t) v[i];
	return oss.str();
}

std::string binToHexStr(const void* p, uint32_t len) {
	std::vector<uint8_t> v;
	for (uint32_t i(0) ; i < len ; i++) v.push_back(((uint8_t*) p)[i]);
	return v8ToHexStr(v);
}

std::vector<uint8_t> hexStrToV8(std::string str) {
	if (str.size() % 2 != 0) str = "0" + str;
	std::vector<uint8_t> v;
	
	for (uint16_t i(0) ; i < str.size() ; i += 2) {
		uint8_t byte(0);
		for (uint8_t j(0) ; j < 2 ; j++) {
			uint8_t m(1);
			if (j == 0) m = 16;
			if (str[i + j] >= '0' && str[i + j] <= '9')
				byte += m*(str[i + j] - '0');
			else if (str[i + j] >= 'A' && str[i + j] <= 'F')
				byte += m*(str[i + j] - 'A' + 10);
			else if (str[i + j] >= 'a' && str[i + j] <= 'f')
				byte += m*(str[i + j] - 'a' + 10);
			else byte += 0;
		}
		v.push_back(byte);
	}
	return v;
}

void hexStrToBin(std::string str, uint8_t* data) {
	std::vector<uint8_t> v(hexStrToV8(str));
	for (uint16_t i(0) ; i < v.size() ; i++) data[i] = v[i];
}

std::string toUpper(std::string str) {
	std::string STR;
	for (uint16_t i(0) ; i < str.size() ; i++) {
		if (str[i] >= 'a' && str[i] <= 'z')
			STR += str[i] - 32;
		else STR += str[i];
	}
	return STR;
}

std::string toLower(std::string STR) {
	std::string str;
	for (uint16_t i(0) ; i < STR.size() ; i++) {
		if (STR[i] >= 'A' && STR[i] <= 'Z')
			str += STR[i] + 32;
		else str += STR[i];
	}
	return str;
}

std::vector<uint8_t> sha256(const uint8_t *data, uint32_t len) {
	std::vector<uint8_t> hash;
	uint8_t hashTmp[32];
	SHA256_CTX sha256;
	SHA256_Init(&sha256);
	SHA256_Update(&sha256, data, len);
	SHA256_Final(hashTmp, &sha256);
	for (uint8_t i(0) ; i < 32 ; i++) hash.push_back(hashTmp[i]);
	return hash;
}

std::vector<uint8_t> sha256sha256(const uint8_t *data, uint32_t len) {
	std::vector<uint8_t> hash;
	hash = sha256(data, len);
	hash = sha256(hash.data(), 32);
	return hash;
}
uint32_t getCompact(uint32_t nCompact) {
	const uint32_t nSize(nCompact >> 24), nWord(nCompact & 0x007fffff);
	if (nSize <= 3) return nWord >> 8*(3 - nSize);
	else return nWord << 8*(nSize - 3); // warning: this has problems if difficulty (uncompacted) ever goes past the 2^32 boundary
}

// Reverse the Endianness of a uint32_t (ABCDEF01 -> 01EFCDAB)
uint32_t invEnd32(uint32_t x) {
	return ((x << 24) & 0xff000000u) | ((x << 8) & 0x00ff0000u) | ((x >> 8) & 0x0000ff00u) | ((x >> 24) & 0x000000ffu);
}

int main() {
	std::cout << "blockHeaderDecode from rieTools, by Pttn" << std::endl;
	std::cout << "Project page: https://github.com/Pttn/rieTools" << std::endl;
	std::cout << "--------------------------------------------------------------------------------" << std::endl;
	
	std::string bhStr;
	std::cout << "Enter a blockheader Hex string: ";
	std::cin  >> bhStr;
	
	bhStr = toLower(bhStr);
	std::cout << "Input: " << bhStr << std::endl;
	if (bhStr.size() < 224)
		std::cerr << "Incomplete or invalid blockheader Hex string!" << std::endl;
	else {
		if (bhStr.size() > 224) {
			std::cerr << "Too long blockheader Hex string, ignoring characters after the 224th." << std::endl;
			bhStr = bhStr.substr(0, 224);
			std::cout << "Truncated input: " << bhStr << std::endl;
		}
		
		if (!validHex(bhStr))
			std::cerr << "Invalid Hex string!" << std::endl;
		else {
			std::cout << "--------------------------------------------------------------------------------" << std::endl;
			uint32_t version(invEnd32(strtol(bhStr.substr(0, 8).c_str(), NULL, 16)));
			std::cout << "Version: " << bhStr.substr(0, 8) << " -> " << version << std::endl;
			std::cout << "Previous Block Hash: " << bhStr.substr(8, 64) << std::endl;
			std::cout << "Merkle Root: " << bhStr.substr(72, 64) << std::endl;
			uint32_t diff(getCompact(invEnd32(strtol(bhStr.substr(136, 8).c_str(), NULL, 16))));
			std::cout << "Difficulty: " << bhStr.substr(136, 8) << " -> " << diff << std::endl;
			uint64_t time(strtoull(bhStr.substr(144, 16).c_str(), NULL, 16));
			std::cout << "Time: " << bhStr.substr(144, 16) << " -> " << invEnd32(((uint32_t*) &time)[1]) << std::endl;
			std::cout << "Offset (X) : " << bhStr.substr(160, 64) << std::endl;
			std::cout << "Sha256^2 (without Offset) (S) : " << v8ToHexStr(sha256sha256(hexStrToV8(bhStr.substr(0, 160)).data(), 80)) << std::endl;
			std::cout << "Sha256^2 (with Offset)        : " << v8ToHexStr(sha256sha256(hexStrToV8(bhStr.substr(0, 224)).data(), 112)) << std::endl;
			std::cout << "--------------------------------------------------------------------------------" << std::endl;
			std::cout << "Proposed solution: n = 2^(D - 1) + S*2^(D - 265) + X, with" << std::endl;
			std::cout << "D = " << diff << std::endl;
			
			std::vector<uint8_t> SV8(32), tmp(sha256sha256(hexStrToV8(bhStr.substr(0, 160)).data(), 80));
			for (uint64_t i(0) ; i < 256 ; i++)
				SV8[i/8] |= (((tmp[i/8] >> (i % 8)) & 1) << (7 - (i % 8)));
			mpz_class S(v8ToHexStr(SV8).c_str(), 16), target(1);
			std::cout << "S = " << S << std::endl;
			mpz_mul_2exp(S.get_mpz_t(), S.get_mpz_t(), diff - 265);
			mpz_mul_2exp(target.get_mpz_t(), target.get_mpz_t(), diff - 1);
			target += S;
			// std::cout << "Target = " << target << std::endl;
			
			std::vector<uint8_t> xV8;
			tmp = hexStrToV8(bhStr.substr(160, 64));
			for (uint8_t i(0) ; i < tmp.size() ; i++) xV8.push_back(tmp[tmp.size() - i - 1]);
			mpz_class X(v8ToHexStr(xV8).c_str(), 16);
			std::cout << "X = " << X << std::endl;
			
			mpz_class n(target + X);
			std::cout << "-> n = " << n << std::endl;
			std::array<std::string, 3> result = {"not prime", "probably prime", "prime"};
			
			uint32_t iters(40);
			std::cout << "n is " << result[mpz_probab_prime_p(n.get_mpz_t(), iters)] << std::endl;
			n += 4;
			std::cout << "n + 4 is " << result[mpz_probab_prime_p(n.get_mpz_t(), iters)] << std::endl;
			n += 2;
			std::cout << "n + 6 is " << result[mpz_probab_prime_p(n.get_mpz_t(), iters)] << std::endl;
			n += 4;
			std::cout << "n + 10 is " << result[mpz_probab_prime_p(n.get_mpz_t(), iters)] << std::endl;
			n += 2;
			std::cout << "n + 12 is " << result[mpz_probab_prime_p(n.get_mpz_t(), iters)] << std::endl;
			n += 4;
			std::cout << "n + 16 is " << result[mpz_probab_prime_p(n.get_mpz_t(), iters)] << std::endl;
			std::cout << "Probably prime means having a probability of 2^(-" << 2*iters << ") of being a composite number identified as a prime." << std::endl;
		}
	}
    return 0;
}
