#ifndef PACKET_SNIFFER_H
#define PACKET_SNIFFER_H

#include <pcap.h>
#include <string>
#include <vector>
#include <functional>
#include <memory>

class PacketSniffer {
public:
    PacketSniffer();
    ~PacketSniffer();

    bool initialize(const std::string& interface = "");
    void startCapture(int packetCount = -1);
    void stopCapture();
    void setFilter(const std::string& filterExpression);
    void setPacketHandler(std::function<void(const u_char*, int)> handler);

    std::vector<std::string> getAvailableInterfaces();

private:
    pcap_t* handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    bpf_program fp;
    std::function<void(const u_char*, int)> packetHandler;
    bool isCapturing;

    static void packetHandlerWrapper(u_char* user, const struct pcap_pkthdr* pkthdr, const u_char* packet);
};

#endif