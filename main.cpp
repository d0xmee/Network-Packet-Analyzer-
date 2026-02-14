#include <iostream>
#include <memory>
#include <csignal>
#include "packet_sniffer.h"
#include "packet_parser.h"

std::unique_ptr<PacketSniffer> sniffer;

void signalHandler(int signum) {
    std::cout << "\nInterrupt signal (" << signum << ") received.\n";
    if (sniffer) {
        sniffer->stopCapture();
    }
    exit(signum);
}

int main(int argc, char* argv[]) {
    signal(SIGINT, signalHandler);

    std::cout << "=== Network Packet Analyzer ===" << std::endl;
    std::cout << "A tool for cybersecurity analysis" << std::endl;
    std::cout << "================================\n" << std::endl;

    sniffer = std::make_unique<PacketSniffer>();

    auto interfaces = sniffer->getAvailableInterfaces();
    std::cout << "Available network interfaces:" << std::endl;
    for (const auto& iface : interfaces) {
        std::cout << "  - " << iface << std::endl;
    }
    std::cout << std::endl;

    std::string interface = (argc > 1) ? argv[1] : "";
    if (!sniffer->initialize(interface)) {
        std::cerr << "Failed to initialize sniffer!" << std::endl;
        return 1;
    }

    if (argc > 2) {
        sniffer->setFilter(argv[2]);
    }
    else {
        sniffer->setFilter("tcp or udp");
    }

    sniffer->setPacketHandler([](const u_char* packet, int length) {
        PacketParser::parseEthernet(packet, length);
        std::cout << "----------------------------------------" << std::endl;
        });

    int packetCount = (argc > 3) ? std::stoi(argv[3]) : -1;
    sniffer->startCapture(packetCount);

    return 0;
}