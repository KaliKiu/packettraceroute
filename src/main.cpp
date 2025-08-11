
#include "../include/packet_crafting.hpp"
#include "../include/transmission_socket.hpp"
#include "../include/utils.hpp"
#include "../include/json.hpp"
#include <iostream>
#include <fstream>

//
int main(){
    std::ifstream file(Packet::IP_CONFIG_FILE);
    nlohmann::json json;
    file>>json;
    size_t destIPlength =json["destIP"].size();
    
    for(int ipcount = 0; ipcount<destIPlength; ipcount++){
        Packet pack;
        Socket socket;
        socket.createSocket();
        int ttl=1;
        while(socket.quit==false){
            std::vector<uint8_t> packet = pack.buildPackage(ttl,ipcount);
            Packet::writePacketInFile(packet);
            Utils::printHexPacket(packet);
            socket.sendPacket(pack.ippointer,packet);
            std::vector<uint8_t> respondPacket = socket.receivePacket(pack.ippointer,ipcount);
            Utils::printHexPacket(respondPacket);
            ttl++;
        }
    }
}

