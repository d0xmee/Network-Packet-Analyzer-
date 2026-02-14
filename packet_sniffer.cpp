#include "packet_sniffer.h"
#include "packet_parser.h"
#include <iostream>
#include <algorithm>
#include <cstring>

PacketSniffer::PacketSniffer() : handle(nullptr), isCapturing(false) {
    memset(errbuf, 0, sizeof(errbuf));
}

PacketSniffer::~PacketSniffer() {
    stopCapture();
    if (handle) {
        pcap_close(handle);
    }
}

bool PacketSniffer::initialize(const std::string& interface) {
    std::string dev = interface;

    if (dev.empty()) {
        dev = pcap_lookupdev(errbuf);
        if (dev.empty()) {
            std::cerr << "Couldn't find default device: " << errbuf << std::endl;
            return false;
        }
    }

    std::cout << "Using device: " << dev << std::endl;

    handle = pcap_open_live(dev.c_str(), BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        std::cerr << "Couldn't open device " << dev << ": " << errbuf << std::endl;
        return false;
    }

    return true;
}

void PacketSniffer::setFilter(const std::string& filterExpression) {
    if (handle == nullptr) return;

    if (pcap_compile(handle, &fp, filterExpression.c_str(), 0, PCAP_NETMASK_UNKNOWN) == -1) {
        std::cerr << "Couldn't parse filter " << filterExpression << ": " << pcap_geterr(handle) << std::endl;
        return;
    }

    if (pcap_setfilter(handle, &fp) == -1) {
        std::cerr << "Couldn't install filter " << filterExpression << ": " << pcap_geterr(handle) << std::endl;
        return;
    }

    std::cout << "Filter set: " << filterExpression << std::endl;
}

void PacketSniffer::setPacketHandler(std::function<void(const u_char*, int)> handler) {
    packetHandler = handler;
}

void PacketSniffer::startCapture(int packetCount) {
    if (handle == nullptr) {
        std::cerr << "Sniffer not initialized!" << std::endl;
        return;
    }

    isCapturing = true;
    std::cout << "Starting packet capture..." << std::endl;

    pcap_loop(handle, packetCount, packetHandlerWrapper, reinterpret_cast<u_char*>(this));
}

void PacketSniffer::stopCapture() {
    if (isCapturing) {
        pcap_breakloop(handle);
        isCapturing = false;
    }
}

void PacketSniffer::packetHandlerWrapper(u_char* user, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    PacketSniffer* sniffer = reinterpret_cast<PacketSniffer*>(user);
    if (sniffer && sniffer->packetHandler) {
        sniffer->packetHandler(packet, pkthdr->len);
    }
}

std::vector<std::string> PacketSniffer::getAvailableInterfaces() {
    std::vector<std::string> interfaces;
    pcap_if_t* alldevs;
    char errbuf[PCAP_ERRBUF_SIZE];

    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        std::cerr << "Error finding devices: " << errbuf << std::endl;
        return interfaces;
    }

    for (pcap_if_t* d = alldevs; d != nullptr; d = d->next) {
        interfaces.push_back(d->name);
    }

    pcap_freealldevs(alldevs);
    return interfaces;
}