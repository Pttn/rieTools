// (c) 2018 Pttn (https://github.com/Pttn/rieTools)
// Simple tool to check if a number is the base prime of a prime constellation

// Depends on GMP (with its C++ wrapper)
// Compile with 'g++ constellationCheck.cpp -O3 -o constellationCheck -l gmp -l gmpxx'
// Only tested on Linux (Debian 9)
// Edit the offsets vector to adapt to your needs

#include <iostream>
#include <vector>
#include <array>
#include <gmp.h>
#include <gmpxx.h>

bool validDec(const std::string &str) {
	for (uint16_t i(0) ; i < str.size() ; i++) {
		if (!(str[i] >= '0' && str[i] <= '9'))
			return false;
	}
	return true;
}

int main() {
	std::cout << "tupleCheck from rieTools, by Pttn" << std::endl;
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
		std::array<std::string, 3> results = {"not prime", "probably prime", "prime"};
		uint32_t iters(100), offset(0), primes(0);
		mpz_class N(n);
		
		for (uint32_t i(0) ; i < offsets.size() ; i++) {
			offset += offsets[i];
			N += offsets[i];
			uint32_t result(mpz_probab_prime_p(N.get_mpz_t(), iters));
			std::cout << "n + " << offset << " is " << results[result] << std::endl;
			if (result != 0) primes++;
		}
		
		std::cout << "--------------------------------------------------------------------------------" << std::endl;
		
		if (primes == offsets.size())
			std::cout << "Congratulations, you found a prime constellation :D (provided that the given 'constellation type' is a valid one) !" << std::endl;
		else
			std::cout << "Sorry, only " << primes << " numbers out of " << offsets.size() << " are prime." << std::endl;
		
		std::cout << "Probably prime means having a probability of 2^(-" << 2*iters << ") of being a composite number identified as a prime." << std::endl;
	}
	
	return 0;
}
