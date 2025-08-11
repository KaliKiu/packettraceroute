#ifndef TRANSMISSION_SOCKET
#define TRANSMISSION_SOCKET

#include "../include/packet_crafting.hpp"

class Socket{
public:
    static constexpr const char* IP_ADDR = "../data/ip_addr.json";
    static constexpr int MAX_NOREPLY_HOP = 10;
    static constexpr const char* JSON_TRACES_OBJECT = "Traces";
    bool quit;
    uint8_t count;
    int socketfd;
    int socketrcv;
    void createSocket();
    void sendPacket(Packet::ipheader* ippointer,std::vector<uint8_t> packet);
    std::vector<uint8_t> receivePacket(Packet::ipheader* ippointer,int ipcount);
    static void writeToFile(char ip[16],std::string packet,int ipcount);
    void storeQuitErrorInJson(int ipcount,const std::string path);
};
#endif