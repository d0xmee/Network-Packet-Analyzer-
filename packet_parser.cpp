#include "packet_parser.h"
#include <arpa/inet.h>
#include <cstring>
#include <sstream>
#include <iomanip>

std::string PacketParser::macToString(const uint8_t* mac) {
    std::stringstream ss;
    for (int i = 0; i < 6; i++) {
        ss << std::hex << std::setfill('0') << std::setw(2) << (int)mac[i];
        if (i < 5) ss << ":";
    }
    return ss.str();
}

std::string PacketParser::ipToString(uint32_t ip) {
    struct in_addr addr;
    addr.s_addr = ip;
    return std::string(inet_ntoa(addr));
}

void PacketParser::printPacketInfo(const std::string& protocol,
    const std::string& src,
    const std::string& dest,
    int length) {
    std::cout << "[" << protocol << "] "
        << src << " -> " << dest
        << " | Length: " << length << " bytes" << std::endl;
}

void PacketParser::parseEthernet(const u_char* packet, int length) {
    EthernetHeader* eth = (EthernetHeader*)packet;

    std::cout << "\n=== Ethernet Frame ===" << std::endl;
    std::cout << "Source MAC: " << macToString(eth->srcMAC) << std::endl;
    std::cout << "Destination MAC: " << macToString(eth->destMAC) << std::endl;
    std::cout << "Type: 0x" << std::hex << ntohs(eth->type) << std::dec << std::endl;

    if (ntohs(eth->type) == 0x0800) { 
        parseIP(packet + sizeof(EthernetHeader), length - sizeof(EthernetHeader));
    }
}

void PacketParser::parseIP(const u_char* packet, int length) {
    IPHeader* ip = (IPHeader*)packet;
    int ipHeaderLength = (ip->versionIHL & 0x0F) * 4;

    std::cout << "=== IP Packet ===" << std::endl;
    std::cout << "Source IP: " << ipToString(ip->srcIP) << std::endl;
    std::cout << "Destination IP: " << ipToString(ip->destIP) << std::endl;
    std::cout << "Protocol: " << (int)ip->protocol << std::endl;

    switch (ip->protocol) {
    case 6:
        parseTCP(packet + ipHeaderLength, length - ipHeaderLength);
        break;
    case 17:
        parseUDP(packet + ipHeaderLength, length - ipHeaderLength);
        break;
    }
}

void PacketParser::parseTCP(const u_char* packet, int length) {
    TCPHeader* tcp = (TCPHeader*)packet;
    int tcpHeaderLength = ((tcp->offsetReserved & 0xF0) >> 4) * 4;

    std::cout << "=== TCP Segment ===" << std::endl;
    std::cout << "Source Port: " << ntohs(tcp->srcPort) << std::endl;
    std::cout << "Destination Port: " << ntohs(tcp->destPort) << std::endl;
    std::cout << "Sequence Number: " << ntohl(tcp->seqNum) << std::endl;
    std::cout << "Acknowledgement Number: " << ntohl(tcp->ackNum) << std::endl;

    std::cout << "Flags: ";
    if (tcp->flags & 0x01) std::cout << "FIN ";
    if (tcp->flags & 0x02) std::cout << "SYN ";
    if (tcp->flags & 0x04) std::cout << "RST ";
    if (tcp->flags & 0x08) std::cout << "PSH ";
    if (tcp->flags & 0x10) std::cout << "ACK ";
    if (tcp->flags & 0x20) std::cout << "URG ";
    std::cout << std::endl;

    int payloadLength = length - tcpHeaderLength;
    if (payloadLength > 0) {
        std::cout << "Payload (" << payloadLength << " bytes):" << std::endl;
        printHexDump(packet + tcpHeaderLength, std::min(payloadLength, 64));
    }
}

void PacketParser::parseUDP(const u_char* packet, int length) {
    UDPHeader* udp = (UDPHeader*)packet;

    std::cout << "=== UDP Datagram ===" << std::endl;
    std::cout << "Source Port: " << ntohs(udp->srcPort) << std::endl;
    std::cout << "Destination Port: " << ntohs(udp->destPort) << std::endl;
    std::cout << "Length: " << ntohs(udp->length) << std::endl;
}

void PacketParser::printHexDump(const u_char* data, int length) {
    for (int i = 0; i < length; i++) {
        if (i % 16 == 0) {
            std::cout << std::endl << std::setfill('0') << std::setw(4) << std::hex << i << ": ";
        }
        std::cout << std::setfill('0') << std::setw(2) << std::hex << (int)data[i] << " ";

        if (i % 16 == 7) std::cout << " ";
    }
    std::cout << std::dec << std::endl;
}