#include "rieTools.h"

void error(std::string message) {std::cerr << message << std::endl;}

std::default_random_engine eng((std::random_device())());

uint8_t rand(uint8_t min, uint8_t max) {
	if (min > max) std::swap(min, max);
	std::uniform_int_distribution<uint8_t> urd(min, max);
	uint8_t n(urd(eng));
	return n;
}

bool validHex(const std::string &str) {
	for (uint16_t i(0) ; i < str.size() ; i++) {
		if (!((str[i] >= '0' && str[i] <= '9')
		   || (str[i] >= 'A' && str[i] <= 'F')
		   || (str[i] >= 'a' && str[i] <= 'f')))
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

// GMP base 58 digits    : 0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuv
// Bitcoin base 58 digits: 123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz
// Ascii                          ⋅⋅⋅⋅⋅⋅⋅⋅⋅⋅⋅⋅⋅⋅⋅⋅⋅⋅⋅⋅⋅⋅⋅⋅⋅⋅⋅⋅⋅⋅⋅⋅ !"#$%&'()*+,-./0123465789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\]^_`abcdefghijklmnopqrstuvwxyz{|}-⋅
const std::string b58GmpBtcTable("000000000000000000000000000000000000000000000000123456789A0000000BCDEFGHJKLMNPQRSTUVWXYZabc000000defghijkmnopqrstuvwxyz000000000");
const std::string b58BtcGmpTable("zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz012345678zzzzzzz9ABCDEFGzHIJKLzMNOPQRSTUVWzzzzzzXYZabcdefghzijklmnopqrstuvzzzzz");

std::string gmp58Tobtc58(const std::string gmp58Str) {
	std::string btc58Str;
	for (uint64_t i(0) ; i < gmp58Str.size() ; i++) {
		if (b58GmpBtcTable[gmp58Str[i]] == '0') {
			std::cerr << "gmp58Tobtc58: invalid Base58 (GMP) string!" << std::endl;
			return "1";
		}
		btc58Str += b58GmpBtcTable[gmp58Str[i]];
	}
	return btc58Str;
}

std::string btc58Togmp58(const std::string btc58Str) {
	std::string gmp58Str;
	for (uint64_t i(0) ; i < btc58Str.size() ; i++) {
		if (b58BtcGmpTable[btc58Str[i]] == 'z') {
			std::cerr << "btc58Togmp58: invalid Base58 (Bitcoin) string!" << std::endl;
			return "0";
		}
		gmp58Str += b58BtcGmpTable[btc58Str[i]];
	}
	return gmp58Str;
}

std::string v8ToB58Str(const std::vector<uint8_t> v8) {
	mpz_class data;
	mpz_import(data.get_mpz_t(), v8.size(), 1, 1, 0, 0, v8.data());
	char c[255];
	mpz_get_str(c, 58, data.get_mpz_t());
	return gmp58Tobtc58(c);
}

std::vector<uint8_t> b58StrToV8(std::string btc58Str) {
	mpz_class data(btc58Togmp58(btc58Str).c_str(), 58);
	uint64_t size((mpz_sizeinbase(data.get_mpz_t(), 2) + 7)/8);
	std::vector<uint8_t> v8(size);
	mpz_export(&v8[0], &size, 1, 1, 0, 0, data.get_mpz_t());
	return v8;
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

std::vector<uint8_t> ripem160(const uint8_t *data, uint32_t len) {
	std::vector<uint8_t> hash;
	uint8_t hashTmp[20];
	RIPEMD160_CTX ripem160;
	RIPEMD160_Init(&ripem160);
	RIPEMD160_Update(&ripem160, data, len);
	RIPEMD160_Final(hashTmp, &ripem160);
	for (uint8_t i(0) ; i < 20 ; i++) hash.push_back(hashTmp[i]);
	return hash;
}

std::string prvBinToWif(const std::vector<uint8_t> &prvBin) {
	std::vector<uint8_t> tmp(prvBin);
	tmp.insert(tmp.begin(), 0x80);
	
	std::vector<uint8_t> hash;
	hash = sha256(tmp.data(), 33);
	hash = sha256(hash.data(), 32);
	
	// prvFinal : 80 . prvHex . prvHashHex
	mpz_class prvFinal, prvPre(0x80), prvBin2, prvHash;
	mpz_mul_2exp(prvPre.get_mpz_t(), prvPre.get_mpz_t(), 32*8 + 32);
	mpz_import(prvBin2.get_mpz_t(), 32, 1, 1, 0, 0, prvBin.data());
	mpz_mul_2exp(prvBin2.get_mpz_t(), prvBin2.get_mpz_t(), 32);
	mpz_import(prvHash.get_mpz_t(),  4, 1, 1, 0, 0, hash.data());
	prvFinal = prvPre + prvBin2 + prvHash;
	
	char c[255];
	mpz_get_str(c, 58, prvFinal.get_mpz_t());
	return gmp58Tobtc58(c);
}

std::vector<uint8_t> addrToScriptPubKey(std::vector<uint8_t> addr) {
	std::vector<uint8_t> spk = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
	if (addr.size() != 25)
		std::cerr << "Invalid address length!" << std::endl;
	else {
		// Validate checksum
		std::vector<uint8_t> addressHash;
		addressHash = sha256(addr.data(), 21);
		addressHash = sha256(addressHash.data(), 32);
		
		if (*((uint32_t*) &addr[21]) != *((uint32_t*) &addressHash[0]))
			std::cerr << "Invalid checksum!" << std::endl;
		else {
			for (uint8_t i(0) ; i < 20 ; i++) spk[i] = addr[i + 1];
		}
	}
	return spk;
}

bool ecdsaPubGen(const std::vector<uint8_t> &prvBin, std::string &pubHexFull, std::string &pubHexCompressed) {
	bool ok(true);
	// Reference https://wiki.openssl.org/index.php/Elliptic_Curve_Cryptography
	EC_GROUP *group;
	if ((group = EC_GROUP_new_by_curve_name(NID_secp256k1)) == NULL) {
		error("Unable to init Secp256k1 curve :|");
		ok = false;
	}
	else {
		BN_CTX *ctx;
		if ((ctx = BN_CTX_new()) == NULL) {
			error("Unable to init Ctx :|");
			ok = false;
		}
		else {
			BIGNUM *bnPrv;
			if ((bnPrv = BN_bin2bn(prvBin.data(), 32, NULL)) == NULL) {
				error("Unable to copy private key :|");
				ok = false;
			}
			else {
				EC_POINT *ecpPub;
				if ((ecpPub = EC_POINT_new(group)) == NULL) {
					error("Unable to init public key point :|");
					ok = false;
				}
				else if (EC_POINT_mul(group, ecpPub, bnPrv, NULL, NULL, ctx) != 1) {
					error("Unable to calculate public key :|");
					ok = false;
				}
				else {
					EC_KEY *ecKey;
					if ((ecKey = EC_KEY_new_by_curve_name(NID_secp256k1)) == NULL) {
						error("Unable to init public key :|");
						ok = false;
					}
					else if (EC_KEY_set_private_key(ecKey, bnPrv) != 1) {
						error("Unable to set private key :|");
						ok = false;
					}
					else if (EC_KEY_set_public_key(ecKey, ecpPub) != 1) {
						error("Unable to set public key :|");
						ok = false;
					}
					else {
						char *pubHexFullTmp(NULL), *pubHexCompressedTmp(NULL);
						if ((pubHexFullTmp = EC_POINT_point2hex(group, ecpPub, (point_conversion_form_t) 4, ctx)) == NULL) {
							error("Unable to extract full public key :|");
							ok = false;
						}
						else if ((pubHexCompressedTmp = EC_POINT_point2hex(group, ecpPub, (point_conversion_form_t) 2, ctx)) == NULL) {
							error("Unable to extract compressed public key :|");
							ok = false;
						}
						else {
							pubHexFull = pubHexFullTmp;
							pubHexCompressed = pubHexCompressedTmp;
							free(pubHexFullTmp);
							free(pubHexCompressedTmp);
						}
						EC_KEY_free(ecKey);
					}
					EC_POINT_free(ecpPub);
				}
				BN_free(bnPrv);
			}
			BN_CTX_free(ctx);
		}
		EC_GROUP_free(group);
	}
	
	return ok;
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

uint32_t constellationCheck(mpz_class n, std::vector<uint64_t> offsets, uint32_t iters, bool verbose) {
	const std::array<std::string, 3> results = {"not prime", "probably prime", "prime"};
	uint32_t offset(0), primes(0);
	
	if (verbose) std::cout << "Length: " << mpz_sizeinbase(n.get_mpz_t(), 2) << " bits, " << mpz_sizeinbase(n.get_mpz_t(), 10) << " digits in base 10" << std::endl;
	
	for (uint32_t i(0) ; i < offsets.size() ; i++) {
		offset += offsets[i];
		n += offsets[i];
		uint32_t result(mpz_probab_prime_p(n.get_mpz_t(), iters));
		if (verbose) std::cout << "n + " << offset << " is " << results[result] << std::endl;
		if (result != 0) primes++;
	}
	
	if (verbose) std::cout << "Probably prime means having a probability of 2^(-" << 2*iters << ") of being a composite number identified as a prime." << std::endl;
	return primes;
}
