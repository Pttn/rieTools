// (c) 2018-2019 Pttn (https://github.com/Pttn/rieTools)
// Simple tool to check if a number is the base prime of a prime constellation
// Only tested on Linux (Debian 9)
// Edit the offsets vector to adapt to your needs

#include "rieTools.h"

bool validDec(const std::string &str) {
	for (uint16_t i(0) ; i < str.size() ; i++) {
		if (!(str[i] >= '0' && str[i] <= '9'))
			return false;
	}
	return true;
}

int main() {
	std::cout << "constellationCheck from rieTools, by Pttn" << std::endl;
	std::cout << "Project page: https://github.com/Pttn/rieTools" << std::endl;
	std::cout << "--------------------------------------------------------------------------------" << std::endl;
	std::vector<uint64_t> offsets = {0, 4, 2, 4, 2, 4};
	
	uint64_t offsetTemp(0);
	std::cout << "Constellation type: (";
	for (std::vector<uint64_t>::size_type i(0) ; i < offsets.size() ; i++) {
		offsetTemp += offsets[i];
		if (offsetTemp == 0) std::cout << "n";
		else std::cout << "n + " << offsetTemp;
		if (i != offsets.size() - 1) std::cout << ", ";
	}
	std::cout << "), length " << offsets.size() << std::endl;
	
	std::string n;
	std::cout << "Enter an integer positive number in base 10:" << std::endl << "n = ";
	std::cin >> n;
	
	std::cout << "--------------------------------------------------------------------------------" << std::endl;
	
	if (!validDec(n))
		std::cerr << "Invalid number!" << std::endl;
	else {
		mpz_class N(n);
		
		uint32_t primes(constellationCheck(N, offsets, 100, true));
		std::cout << "--------------------------------------------------------------------------------" << std::endl;
		if (primes == offsets.size())
			std::cout << "Congratulations, you found a prime constellation :D (provided that the given 'constellation type' is a valid one) !" << std::endl;
		else
			std::cout << "Sorry, only " << primes << " numbers out of " << offsets.size() << " are prime." << std::endl;
	}
	
	return 0;
}
