#ifndef TRANSMISSION_SOCKET
#define TRANSMISSION_SOCKET

#include "../include/packet_crafting.hpp"

class Socket{
public:
    static constexpr const char* IP_ADDR = "../data/ip_addr.json";
    static constexpr int MAX_NOREPLY_HOP = 10;
    static constexpr const char* JSON_TRACES_OBJECT = "Traces";
    static constexpr const char* JSON_HOP_COUNT_KEY = "Hop";
    bool quit;
    uint8_t count;
    int socketfd;
    int socketrcv;
    void createSocket();
    void sendPacket(Packet::ipheader* ippointer,std::vector<uint8_t> packet);
    std::vector<uint8_t> receivePacket(Packet::ipheader* ippointer,int ipcount,int ttl);
    static void writeToFile(char ip[16],std::string packet,int ipcount,int ttl);
    void jsonKeyValuePair(int ipcount,const std::string& Key,int Value, const std::string path);
    void jsonKeyValuePair(int ipcount,const std::string& Key,const std::string& Value, const std::string path);
};
#endif