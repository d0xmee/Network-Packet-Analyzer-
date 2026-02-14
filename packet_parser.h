#ifndef PACKET_PARSER_H
#define PACKET_PARSER_H

#include <cstdint>
#include <string>
#include <iostream>
#include <iomanip>

struct EthernetHeader {
    uint8_t destMAC[6];
    uint8_t srcMAC[6];
    uint16_t type;
};


struct IPHeader {
    uint8_t versionIHL;
    uint8_t tos;
    uint16_t totalLength;
    uint16_t id;
    uint16_t fragmentOffset;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t checksum;
    uint32_t srcIP;
    uint32_t destIP;
};


struct TCPHeader {
    uint16_t srcPort;
    uint16_t destPort;
    uint32_t seqNum;
    uint32_t ackNum;
    uint8_t offsetReserved;
    uint8_t flags;
    uint16_t window;
    uint16_t checksum;
    uint16_t urgentPtr;
};


struct UDPHeader {
    uint16_t srcPort;
    uint16_t destPort;
    uint16_t length;
    uint16_t checksum;
};

class PacketParser {
public:
    static void parseEthernet(const u_char* packet, int length);
    static void parseIP(const u_char* packet, int length);
    static void parseTCP(const u_char* packet, int length);
    static void parseUDP(const u_char* packet, int length);
    static void printHexDump(const u_char* data, int length);
    static std::string macToString(const uint8_t* mac);
    static std::string ipToString(uint32_t ip);

private:
    static void printPacketInfo(const std::string& protocol,
        const std::string& src,
        const std::string& dest,
        int length);
};

#endif