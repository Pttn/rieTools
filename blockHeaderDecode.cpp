// (c) 2018-2019 Pttn (https://github.com/Pttn/rieTools)
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
			std::string timeSubStr(bhStr.substr(136, 16)), difficultySubStr(bhStr.substr(152, 8));
			for (uint64_t i(0) ; i < 16 ; i++) bhStr[144 + i] = timeSubStr[i];
			for (uint64_t i(0) ; i < 8 ; i++)  bhStr[136 + i] = difficultySubStr[i];
			std::cout << "--------------------------------------------------------------------------------" << std::endl;
			mpz_class n(blockHeaderDecode(bhStr, true));
			std::vector<uint64_t> offsets = {0, 4, 2, 4, 2, 4};
			constellationCheck(n, offsets, 40, true);
		}
	}
    return 0;
}
