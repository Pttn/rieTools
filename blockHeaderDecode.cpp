// (c) 2018 Pttn (https://github.com/Pttn/rieTools)
// Simple Riecoin Blockheader decoder, simply decomposes the block header and show if the numbers in the 6-tuple are prime
// You must use strings from getblockheader
// The official FAQ may help: http://riecoin.org/faq.html

// To get any block header, run getblockhash and getblockheader commands in the Debug Console in Riecoin-Qt
// Example for Block 1000000:
// getblockhash 1000000 -> 0782988fb7c15f1254c2b76b34a3dfdf99620829bc757abc4e90e00800f79861
// getblockheader 0782988fb7c15f1254c2b76b34a3dfdf99620829bc757abc4e90e00800f79861 false -> 02000000e5f387ef33ae894a6e13ab37e1c3cd35d6e25db824f20bdf4a3f4952e2c8c3e88a1d76d33c0279fb538765e3638572f65165ff9646d89d3b5a40879d5cb653fd4ff3095c00000000003c05023335aac7c401c3ef938b0e0673b5557350240d47cad658c0e478d8988843fa4e

#include "rieTools.h"

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
			// For some reason, the time and the difficulty are reversed for the Sha256^2 later
			// Reversing these will also give the corresponding submitblock strings
			std::cout << bhStr << std::endl;
			std::string timeSubStr(bhStr.substr(136, 16)), difficultySubStr(bhStr.substr(152, 8));
			for (uint64_t i(0) ; i < 16 ; i++) bhStr[144 + i] = timeSubStr[i];
			for (uint64_t i(0) ; i < 8 ; i++)  bhStr[136 + i] = difficultySubStr[i];
			std::cout << bhStr << std::endl;
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
