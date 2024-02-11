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
	/*void SaveToFile(const char* data) {
		std::ofstream outFile("received_file.txt", std::ios::binary | std::ios::app);
		outFile.write(data, strlen(data));
		outFile.close();
	}*/
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
public:
	RUNClient() {
		data_sent = 0;
	}

	bool TargetFile(std::string file_path) {
		std::ifstream tmp;
		tmp.open(file_path, std::fstream::in | std::fstream::binary);
		if (tmp.fail()) {
			return false;
		}
		tmp.close();
		_file = file_path;
		this->data_sent = 0;
		file.open(_file, std::fstream::binary);
	}

	// Packet sent will NOT be null terminated
	unsigned char* CreatePacket() {
		SHA1 hash;
		char* buffer = NULL;
		unsigned char* packet = NULL;
		buffer = new char[PACKET_SIZE + 1];
		packet = new unsigned char[PACKET_SIZE + CHECKSUM_SIZE + 1]; // Not null terminated

		if (!file.is_open()) {
			return NULL;
		}
		// Sets position to read from to file begging offset by data_sent
		file.seekg(data_sent, file.beg);

		file.read(buffer, PACKET_SIZE);
		data_sent += file.gcount(); // gcount tells how much data was read
		buffer[file.gcount()] = '\0';

		if (file.gcount() == 0) {
			// Return if file has been completely read
			if (file.is_open())
				file.close();
			return NULL;
		}

		hash.update(buffer);

		memcpy(packet, buffer, strrchr(buffer, '\0') - buffer); // Put file data in packet
		memcpy(packet + strlen(buffer), hash.final().c_str(), hash.final().length()); // Put SHA1 hash in packet

		memcpy(packet + strlen(buffer) + hash.final().length(), "\0", 1);

		return packet;
	}

private:
	unsigned long long data_sent;
	std::ifstream file;
};

#endif
