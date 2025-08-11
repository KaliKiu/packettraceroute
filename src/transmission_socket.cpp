#include "../include/packet_crafting.hpp"
#include "../include/transmission_socket.hpp"
#include "../include/utils.hpp"

#include <sys/socket.h>   // socket(), sendto(), recvfrom()
#include <netinet/in.h>   // sockaddr_in, IPPROTO_ICMP
#include <arpa/inet.h>    // inet_addr()
#include <unistd.h>       // close()
#include <cstring>        
#include <iostream>
#include <vector>
#include <cerrno>

    void Socket::createSocket(){
        //set class obj vars
        this->quit=false;
        this->count = 0;
        int socketfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
        if (socketfd < 0) { perror("socket"); return; }

        int on = 1;
        if (setsockopt(socketfd, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0) {
            perror("setsockopt IP_HDRINCL");
            close(socketfd);
            return;
        }
        int socketrcv = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
        std::cout <<"\nsocket created successfully\n";
        this->socketfd = socketfd;
        this->socketrcv = socketrcv;
    }

    void Socket::sendPacket(Packet::ipheader* ippointer,std::vector<uint8_t> packet){
        if(this->socketfd <= 0){
            std::cerr <<"socket not created yet";
            return;
        }
        sockaddr_in destAddr;
        //clear out memory wiht 0
        memset(&destAddr, 0, sizeof(destAddr));
        destAddr.sin_family = AF_INET;
        
        destAddr.sin_addr.s_addr = ippointer->destIP;
    
        ssize_t sent_bytes = sendto(this->socketfd,packet.data(),packet.size(),0,
                                    (struct sockaddr*)&destAddr,sizeof(destAddr));
        if (sent_bytes < 0) {
            perror("sendto");
            close(this->socketfd);
            return;
            }
    }
    std::vector<uint8_t> Socket::receivePacket(Packet::ipheader* ippointer,int ipcount,int ttl) {
        uint8_t recvBuffer[1024];
        sockaddr_in recvAddr;
        socklen_t addrLen = sizeof(recvAddr);

        // Prepare fd_set for select
        fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET(this->socketrcv, &readfds);

        // Set 2-second timeout
        struct timeval timeout;
        timeout.tv_sec = 5;
        timeout.tv_usec = 0;

        // Wait until socket is readable or timeout occurs
        int ret = select(this->socketrcv + 1, &readfds, nullptr, nullptr, &timeout);
        if (ret == -1) {
            perror("select");
            close(this->socketrcv);
            return {};
        } else if (ret == 0) {
            // Timeout, no data available
            printf("Timeout: no data received in %dseconds\n",timeout.tv_sec);
            Socket::jsonKeyValuePair(ipcount,"Timeout Error",ttl,IP_ADDR);
            //check if having to quit;
            if(this->count>MAX_NOREPLY_HOP){
                this->quit=true;
                Socket::jsonKeyValuePair(ipcount,Socket::JSON_HOP_COUNT_KEY,ttl,IP_ADDR);
                Socket::jsonKeyValuePair(ipcount,"Timeout Error","Quit after getting no response after"+std::to_string(Socket::MAX_NOREPLY_HOP),IP_ADDR);
            }else{
                this->count = this->count +1;
            }
            return {};
        }

        // Socket is readable, safe to call recvfrom without blocking
        ssize_t recv_bytes = recvfrom(this->socketrcv, recvBuffer, sizeof(recvBuffer), 0,
                                    (struct sockaddr*)&recvAddr, &addrLen);
        if (recv_bytes < 0) {
            perror("recvfrom");
            close(this->socketrcv);
            return {};
        }

        char ipStr[INET_ADDRSTRLEN];  // buffer for IPv4 address string
        inet_ntop(AF_INET, &(recvAddr.sin_addr), ipStr, sizeof(ipStr));
        uint16_t port = ntohs(recvAddr.sin_port);

        //check if destination already pinged
        uint32_t ipInt = 0;
        if (inet_pton(AF_INET, ipStr, &ipInt) != 1) {
            std::cerr << "Invalid IP string: " << ipStr << std::endl;
        } else {
            if (ippointer->destIP == ipInt) {
                std::cout << "IP matches!" << std::endl;
                //write end array !!IMPLEMENTATIOM!!
                this->quit=true;
            } else {
                
            }
        }
        printf("Received packet from %s:%u\n", ipStr, port);

        std::vector<uint8_t> packet(recvBuffer, recvBuffer + recv_bytes);
        Socket::writeToFile(ipStr, Utils::bytes_to_hex(packet),ipcount,ttl);
        return packet;
    }

    void Socket::writeToFile(char ip[16],std::string packet,int ipcount,int ttl){
        using json = nlohmann::json;
        json json_in;

        std::ifstream inFile(IP_ADDR);
        if (inFile.is_open()) {
            if (inFile.peek() == std::ifstream::traits_type::eof()) {
                // File is empty → initialize new JSON
                json_in = json::object();
            } else {
                try {
                    inFile >> json_in;
                } catch (const std::exception& e) {
                    std::cerr << "Error parsing JSON: " << e.what() << "\n";
                    json_in = json::object(); // reset if parsing fails
                }
            }
            inFile.close();
        } else {
            // File doesn't exist → start fresh
            json_in = json::object();
        }
        //check for object
        if (!json_in.contains(JSON_TRACES_OBJECT)|| !json_in[JSON_TRACES_OBJECT].is_object()) {
            json_in[JSON_TRACES_OBJECT] = json::object();
        }

        //check for sub array
        if(!json_in[JSON_TRACES_OBJECT].contains(std::to_string(ipcount)) || !json_in[JSON_TRACES_OBJECT][std::to_string(ipcount)].is_array()) {
            json_in[JSON_TRACES_OBJECT][std::to_string(ipcount)] = json::array();
        }



            json newIP = {
                {"ip", std::string(ip)},
                {"payload_in_hex", packet},
                {Socket::JSON_HOP_COUNT_KEY,ttl}
            };
            //appand ttl sub array
            json_in[JSON_TRACES_OBJECT][std::to_string(ipcount)].push_back(newIP);
        
            // Save updated JSON back to file
            std::ofstream outFile(IP_ADDR);
            if (outFile.is_open()) {
                outFile << json_in.dump(4);
                outFile.close();
            } else {
                std::cerr << "Error opening output file\n";
            }
    }
    void Socket::jsonKeyValuePair(int ipcount, const std::string& Key,const std::string& Value,const std::string path){
        std::ifstream file_in(path);
        nlohmann::json json;
        file_in >> json;
        nlohmann::json newIP = {
                {Key, Value},
            };
        json[JSON_TRACES_OBJECT][std::to_string(ipcount)].push_back(newIP);
        file_in.close();
        std::ofstream file_out(path);
        file_out <<json.dump(4);
        file_out.close();
    }
    void Socket::jsonKeyValuePair(int ipcount, const std::string& Key,int Value,const std::string path){
        std::ifstream file_in(path);
        nlohmann::json json;
        file_in >> json;
        nlohmann::json newIP;
        newIP[Key]=Value;
        
        json[JSON_TRACES_OBJECT][std::to_string(ipcount)].push_back(newIP);
        file_in.close();
        std::ofstream file_out(path);
        file_out <<json.dump(4);
        file_out.close();
    }


    

