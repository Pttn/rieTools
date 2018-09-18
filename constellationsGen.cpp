// (c) 2018 Pttn (https://github.com/Pttn/rieTools)
// Prime constellations generator, supports wheel factorization (see https://da-data.blogspot.com/2014/03/fast-prime-cluster-search-or-building.html for explanations)

// Depends on GMP (with its C++ wrapper)
// Compile with 'g++ constellationsGen.cpp -O3 -o constellationsGen -l gmp -l gmpxx'
// Only tested on Linux (Debian 9)
// By default, will generate the 100 first constellations of type (n, n + 4, n + 6, n + 10, n + 12, n + 16) without any optimization
// Edit the offsets vector and constellationsGen arguments in the main to adapt to your needs

#include <iostream>
#include <vector>
#include <gmp.h>
#include <gmpxx.h>

// 100 first primes
const std::vector<uint64_t> primes = {2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181, 191, 193, 197, 199, 211, 223, 227, 229, 233, 239, 241, 251, 257, 263, 269, 271, 277, 281, 283, 293, 307, 311, 313, 317, 331, 337, 347, 349, 353, 359, 367, 373, 379, 383, 389, 397, 401, 409, 419, 421, 431, 433, 439, 443, 449, 457, 461, 463, 467, 479, 487, 491, 499, 503, 509, 521, 523, 541};

std::vector<mpz_class> primorials;

void init() {
	mpz_class primorialTemp(1);
	primorials.push_back(1);
	for (uint8_t i(0) ; i < 100 ; i++) {
		primorialTemp *= primes[i];
		primorials.push_back(primorialTemp);
	}
}

/*
	Offsets: set your constellation type.
	pn: Primorial Number
	po: Primorial Offset
	ccount: stops after finding that number of constellations
	detail: show offsets according to the primorials up to this number, which might help choosing pn and po. 0 to not show this detail
	
	pn = 0 and po = 0 to test every numbers, pn = 1 and po = 1 to test only odd numbers
*/
std::vector<uint64_t> constellationsGen(const std::vector<uint64_t> &offsets, uint32_t pn, uint32_t po, uint32_t ccount, uint8_t detail = 0) {
	std::vector<uint64_t> tuplesCount;
	
	uint64_t offsetTemp(0);
	std::cout << "Constellation type: (";
	for (std::vector<uint64_t>::size_type i(0) ; i < offsets.size() ; i++) {
		tuplesCount.push_back(0);
		offsetTemp += offsets[i];
		if (offsetTemp == 0) std::cout << "n";
		else std::cout << "n + " << offsetTemp;
		if (i != offsets.size() - 1) std::cout << ", ";
	}
	tuplesCount.push_back(0);
	std::cout << "), length " << offsets.size() << std::endl;
	
	if (primorials.size() == 0) std::cerr << "You forgot to init the Primorials list!" << std::endl;
	else {
		if (pn > 100) pn = 100;
		mpz_class primorial(1), primorialOffset(po);
		if (pn != 0) primorial = primorials[pn];
		std::cout << "P" << pn << " = " << primorial << std::endl;
		
		mpz_class x(0);
		while (tuplesCount[offsets.size()] < ccount) {
			uint8_t tupleSize(0);
			bool tuple(true);
			mpz_class x2(x + primorialOffset), candidate(x2);
			for (std::vector<uint64_t>::size_type j(0) ; j < offsets.size() ; j++) {
				x2 += offsets[j];
				if (mpz_probab_prime_p(x2.get_mpz_t(), 40) != 0) {
					tupleSize++;
					tuplesCount[tupleSize]++;
				}
				else {
					tuple = false;
					break;
				}
			}
			if (tuple) {
				std::cout << tuplesCount[tupleSize] << " - " << candidate << std::endl;
				if (detail != 0) {
					for (uint16_t j(0) ; j < detail ; j++) {
						std::cout << "  P" << j << " offset = " << candidate % primorials[j] << std::endl;
					}
				}
			}
			x += primorial;
		}
	}
	return tuplesCount;
}

int main() {
	std::cout << "constellationsGen from rieTools, by Pttn" << std::endl;
	std::cout << "Project page: https://github.com/Pttn/rieTools" << std::endl;
	std::cout << "--------------------------------------------------------------------------------" << std::endl;
	init();
	std::vector<uint64_t> offsets = {0, 4, 2, 4, 2, 4};
	std::vector<uint64_t> tuplesCount;
	
	tuplesCount = constellationsGen(offsets, 0, 0, 100, 0);
	std::cout << "Tuples found: (";
	for (uint32_t i(1) ; i < tuplesCount.size() ; i++) {
		std::cout << tuplesCount[i];
		if (i != tuplesCount.size() - 1) std::cout << " ";
	}
	std::cout << ")" << std::endl;
	std::cout << "Ratios: (";
	for (uint32_t i(2) ; i < tuplesCount.size() ; i++) {
		if (tuplesCount[i] != 0) std::cout << ((double) tuplesCount[i - 1])/((double) tuplesCount[i]);
		else std::cout << "inf";
		if (i != tuplesCount.size() - 1) std::cout << " ";
	}
	std::cout << ")" << std::endl;
	
	return 0;
}
