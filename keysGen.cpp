// (c) 2018-2019 Pttn (https://github.com/Pttn/rieTools)
// Simple Riecoin Keys (private, public, address) generator
// By default, will generate 10 addresses

#include "rieTools.h"

void keysGen() {
	std::vector<uint8_t> prvBin;
	// Generate a random binary private key
	for (uint8_t i(0) ; i < 32 ; i++) prvBin.push_back(rand(0x00, 0xFF));
	// Or choose a private key
	// prvBin = hexStrToV8("e9d11db7a625f642f0f8ba9111b29df1f56f03288243d924d449da3805bc52fc");
	
	std::string prvWif(prvBinToWif(prvBin));
	
	std::cout << "Private Key  : Hex " << binToHexStr(prvBin.data(), 32) << std::endl;
	std::cout << "               Wif " << prvWif << std::endl;
	
	std::string pubHexFull, pubHexCompressed;
	if (!ecdsaPubGen(prvBin, pubHexFull, pubHexCompressed)) {
		error("Unable to generate the public key :|");
		exit(-1);
	}
	
	// Reference https://en.bitcoin.it/wiki/Technical_background_of_version_1_Bitcoin_addresses
	std::vector<uint8_t> sha256HashTmp(sha256(hexStrToV8(pubHexCompressed).data(), 33)),
	                   ripem160HashTmp(ripem160(sha256HashTmp.data(), 32));
	
	std::vector<uint8_t> addBin(ripem160HashTmp);
	addBin.insert(addBin.begin(), 0x3C); // Riecoin addresses prefix
	sha256HashTmp = sha256sha256(addBin.data(), 20 + 1);
	for (uint8_t i(0) ; i < 4 ; i++) addBin.push_back(sha256HashTmp[i]);
	
	std::cout << "Public Key   : Hex130 " << toLower(pubHexFull) << std::endl; // To Lower Case
	std::cout << "               Hex66  " << toLower(pubHexCompressed) << std::endl;
	std::cout << "Address      : " << v8ToB58Str(addBin) << std::endl;
	std::cout << "ScriptPubKey : " << v8ToHexStr(addrToScriptPubKey(addBin)) << std::endl;
}

int main() {
	uint32_t keys(10);
	std::cout << "keysGen from rieTools, by Pttn" << std::endl;
	std::cout << "Project page: https://github.com/Pttn/rieTools" << std::endl;
	for (uint32_t i(0) ; i < keys ; i++) {
		std::cout << "--------------------------------------------------------------------------------" << std::endl;
		keysGen();
	}
    return 0;
}
