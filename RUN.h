#include <iostream>
#include "Net.h"
#include <stdio.h>
#include <iostream>
#include <fstream>
#include "Net.h"
#include "sha1.hpp"

// The following values are represented as bytes
#define CHECKSUM_SIZE 40 // 40 characters long
// Max packet size will be 256 bytes
// This variable is used to determine how much data should be read from a file
//	which is why the CHECKSUM_SIZE is subtracted from it since the checksum will
//	be appended to the end of the packet
#define PACKET_SIZE 256 - CHECKSUM_SIZE 

#ifndef RUN_H
#define RUN_H

class RUN {
public:
	virtual void HandlePacket(unsigned char* data) {
		// Client will use to handle response from server
		// Server will use to handle packets sent from client
		//	i.e. verifying packet using SHA1 checksum
	}

protected:
	std::string _file; // Will be used for inputting data for client and outputting data as server

private:

};

class RUNServer : RUN {

public:
	RUNServer() {
	}

	void HandlePacket(unsigned char* data) override {
		const unsigned char* fileData = data;
		size_t dataSize = strlen(reinterpret_cast<const char*>(fileData));
		const unsigned char* receivedChecksum = fileData + dataSize;


		SHA1 hash;
		hash.update(reinterpret_cast<const char*>(fileData));


		std::string calculatedChecksum = hash.final();

		if (calculatedChecksum == reinterpret_cast<const char*>(receivedChecksum)) {
			SaveToFile(fileData);
			std::cout << "Checksum matched. Data saved to file.\n";
		}
		else {
			std::cout << "Checksum mismatch. Data corrupted.\n";
		}
	}

private:
	void SaveToFile(const unsigned char* packet) {
		const char* filename = reinterpret_cast<const char*>(packet);

		size_t nullPos = strlen(filename);

		std::string fileNameStr(filename, nullPos);

		std::ofstream outFile(fileNameStr, std::ios::binary | std::ios::app);

		if (!outFile.is_open()) {
			std::cerr << "Failed to open file for writing: " << fileNameStr << std::endl;
			return;
		}

		outFile.write(reinterpret_cast<const char*>(packet) + nullPos + 1, PACKET_SIZE - nullPos - 1);

		outFile.close();
	}
};


class RUNClient : RUN {
};

#endif
