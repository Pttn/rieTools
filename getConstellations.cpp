// (c) 2019 Pttn (https://github.com/Pttn/rieTools)
// Extract prime constellations from Riecoin blockchain via Riecoin-Qt
// Please replace username, password, host and port to appropriate values

#include <fstream>
#include <jansson.h>
#include <curl/curl.h>
#include "rieTools.h"

CURL *curl(curl_easy_init());
const std::string username("User"), password("Pass"), host("127.0.0.1");
const uint16_t port(28332);

std::string getUserPass() {
	std::ostringstream oss;
	oss << username << ":" << password;
	return oss.str();
}

std::string getHostPort() {
	std::ostringstream oss;
	oss << "http://" << host << ":" << port << "/";
	return oss.str();
}

static size_t curlWriteCallback(void *data, size_t size, size_t nmemb, std::string *s) {
	s->append((char*) data, size*nmemb);
	return size*nmemb;
}

json_t* sendRPCCall(const std::string& req) {
	std::string s;
	json_t *jsonObj(NULL);
	
	if (curl) {
		json_error_t err;
		curl_easy_setopt(curl, CURLOPT_URL, getHostPort().c_str());
		curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long) strlen(req.c_str()));
		curl_easy_setopt(curl, CURLOPT_POSTFIELDS, req.c_str());
		curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curlWriteCallback);
		curl_easy_setopt(curl, CURLOPT_WRITEDATA, &s);
		curl_easy_setopt(curl, CURLOPT_USERPWD, getUserPass().c_str());
		curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10);
		
		const CURLcode cc(curl_easy_perform(curl));
		if (cc != CURLE_OK)
			std::cerr << __func__ << ": curl_easy_perform() failed :| - " << curl_easy_strerror(cc) << std::endl;
		else {
			jsonObj = json_loads(s.c_str(), 0, &err);
			if (jsonObj == NULL)
				std::cerr << __func__ << ": JSON decoding failed :| - " << err.text << std::endl;
		}
	}
	
	return jsonObj;
}

int main() {
	std::cout << "getConstellations from rieTools, by Pttn" << std::endl;
	std::cout << "Project page: https://github.com/Pttn/rieTools" << std::endl;
	std::cout << "--------------------------------------------------------------------------------" << std::endl;
	
	std::cout << "Ensure that your wallet accepts RPC requests, and do not forget to set the login" << std::endl;
	std::cout << "data properly before compiling." << std::endl;
	
	std::cout << "--------------------------------------------------------------------------------" << std::endl;
	
	std::string path("None"), test("No");
	uint32_t start(0), end(0);
	std::cout << "Get constellations from Block ";
	std::cin >> start;
	std::cout << "to Block ";
	std::cin >> end;
	std::cout << "File path to save constellations (None for not saving and showing instead): ";
	std::cin >> path;
	std::cout << "Save/show number of primes (yes or everything else for no): ";
	std::cin >> test;
	
	std::ofstream file;
	
	if (path != "None") {
		file = std::ofstream(path);
		if (!file) std::cerr << "Unable to open file :|... Saving disabled." << std::endl;
		else std::cout << path << " successfully opened! Saving constellations..." << std::endl;
	}
	
	for (uint32_t i(start) ; i <= end ; i++) {
		json_t *getblockhash(NULL), *getblockheader(NULL);
		std::string hash, blockHeaderHex;
		std::ostringstream oss1, oss2;
		oss1 << "{\"method\": \"getblockhash\", \"params\": [" << i << "], \"id\": 0}\n";
		getblockhash = sendRPCCall(oss1.str());
		if (getblockhash == NULL || json_is_null(json_object_get(getblockhash, "result"))) {
			std::cerr << "Unable to get block hash :|..." << std::endl;
			exit(-1);
		}
		hash = json_string_value(json_object_get(getblockhash, "result"));
		// std::cout << "Received: " << json_dumps(getblockhash, JSON_COMPACT) << std::endl;
		// std::cout << "Block Hash = " << hash << std::endl;
		oss2 << "{\"method\": \"getblockheader\", \"params\": [\"" << hash << "\", false], \"id\": 0}\n";
		getblockheader = sendRPCCall(oss2.str());
		if (getblockheader == NULL || json_is_null(json_object_get(getblockheader, "result"))) {
			std::cerr << "Unable to get block header :|..." << std::endl;
			exit(-1);
		}
		blockHeaderHex = json_string_value(json_object_get(getblockheader, "result"));
		// std::cout << "Received: " << json_dumps(getblockheader, JSON_COMPACT) << std::endl;
		// std::cout << "Block header: " << blockHeaderHex << std::endl;
		
		// For some reason, the time and the difficulty are reversed for the Sha256^2 later
		// Reversing these will also give the corresponding submitblock strings
		std::string timeSubStr(blockHeaderHex.substr(136, 16)), difficultySubStr(blockHeaderHex.substr(152, 8));
		for (uint64_t i(0) ; i < 16 ; i++) blockHeaderHex[144 + i] = timeSubStr[i];
		for (uint64_t i(0) ; i < 8 ; i++)  blockHeaderHex[136 + i] = difficultySubStr[i];
		mpz_class n(blockHeaderDecode(blockHeaderHex));
		std::vector<uint64_t> offsets = {0, 4, 2, 4, 2, 4};
		uint16_t primes(constellationCheck(n, offsets, 40));
		if (file) {
			file << n;
			if (test == "yes") file << " (" << primes << "/" << offsets.size() << ")";
			file << std::endl;
		}
		else {
			std::cout << i << " - " << n;
			if (test == "yes") std::cout << " (" << primes << "/" << offsets.size() << ")";
			std::cout << std::endl;
		}
	}
	
	if (file) {
		std::cout << "Finished :D !" << std::endl;
	}
	
    return 0;
}
