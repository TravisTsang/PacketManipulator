/*
    PROGRAM STRUCTURE:
    1. Create virtual DNS server with loopback address (127.0.0.1)
    2. Browser sends all requests to this DNS server first
    3. If request is not for blocked domain, let it pass
    4. If request is for blocked domain, send NXDOMAIN response
*/

#include <winsock2.h>
#include <ws2tcpip.h>  
#include <windows.h>
#include <cstdint>
#include <iostream>
#include <unordered_set>
#include <unordered_map>
#include <string>

volatile bool is_running = true;
const int DNS_PORT       = 53;
const int UPSTREAM_PORT  = 53;
const char* UPSTREAM_DNS = "8.8.8.8";
const std::unordered_set<std::string> BLOCKED_DOMAINS = 
{
    "youtube.com"
};

struct DNSHeader 
{
    uint16_t id;
    uint16_t flags;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
};

void restore_dns()
{
    system("netsh interface ip set dns \"Wi-Fi\" dhcp");
    std::cout << "DNS restored to automatic\n";
}


BOOL WINAPI ctrl_c_event(DWORD event)
{
    if (event == CTRL_C_EVENT || event == CTRL_BREAK_EVENT)
    {
        is_running = false;
        restore_dns();
        std::cout << "Stopping Program" << std::endl;
        std::cout.flush();
        return TRUE;
    }
    return FALSE;
}

void set_dns(const std::string& dns)
{
    std::string cmd = "netsh interface ip set dns \"Wi-Fi\" static " + dns + " validate=no";
    system(cmd.c_str());
    std::cout << "DNS set to " << dns << "\n";
}

std::string parse_dns_name(const uint8_t* data, int& offset, int dns_length) 
{
    std::string name;

    while (offset < dns_length) 
    {
        uint8_t length = data[offset];

        if (length == 0)
        {
            offset++;  
            break;
        }

        if ((length & 0xC0) == 0xC0) 
        {                       
            int new_offset = ((length & 0x3F) << 8) | data[offset + 1];
            offset += 2;
            int ptr = new_offset;
            name += parse_dns_name(data, ptr, dns_length);     
            return name;
        }

        if (!name.empty()) 
        {
            name += ".";
        }

        offset++;
        name.append(reinterpret_cast<const char*>(data + offset), length);
        offset += length;
    }

    return name;
}

int build_nxdomain(const uint8_t* query, int query_len, uint8_t* response)
 {
    memcpy(response, query, query_len);

    DNSHeader* hdr = reinterpret_cast<DNSHeader*>(response);
    uint16_t flags = ntohs(hdr->flags);

    flags |= (1 << 15);     
    flags |= (1 << 10);     
    flags &= ~0xF;        
    flags |= 0x3;          

    hdr->flags   = htons(flags);
    hdr->ancount = 0;
    hdr->nscount = 0;
    hdr->arcount = 0;

    return query_len;
}

int forward_query(const uint8_t* query, int query_len, uint8_t* response)
{
    SOCKET sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock == INVALID_SOCKET) 
    {
        return -1;
    }

    DWORD timeout = 3000; 
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout));

    sockaddr_in upstream{};
    upstream.sin_family = AF_INET;
    upstream.sin_port = htons(UPSTREAM_PORT);
    upstream.sin_addr.s_addr = inet_addr(UPSTREAM_DNS);

    sendto(sock, reinterpret_cast<const char*>(query), query_len, 0,
           reinterpret_cast<sockaddr*>(&upstream), sizeof(upstream));

    int len = sizeof(upstream);
    int resp_len  = recvfrom(sock, reinterpret_cast<char*>(response), 512, 0,
    reinterpret_cast<sockaddr*>(&upstream), &len);
    closesocket(sock);
    return resp_len;
}



int main() 
{   
    WSAData wsa_data;
    WSAStartup(MAKEWORD(2, 2), &wsa_data);

    SetConsoleCtrlHandler(ctrl_c_event, TRUE);

    SOCKET server_sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (server_sock == INVALID_SOCKET) 
    {
        std::cerr << "Socket Failed:\n";
        return 1;
    }

    int opt = 1;
    setsockopt(server_sock, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char*>(&opt), sizeof(opt));

    sockaddr_in server_addr{};
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(DNS_PORT);
    server_addr.sin_addr.s_addr = inet_addr("127.0.0.1");

    if (bind(server_sock, reinterpret_cast<sockaddr*>(&server_addr), sizeof(server_addr)) < 0) 
    {
        std::cerr << "Bind Failed:\n";
        return 1;
    }

    std::cout << "DNS server listening on 127.0.0.1:" << DNS_PORT << "\n";
    std::cout.flush();

    set_dns("127.0.0.1");
    system("ipconfig /flushdns");

    uint8_t buffer[512], response[512];
    sockaddr_in client_addr{};
    int client_len = sizeof(client_addr);

    while (is_running) 
    {
        int recv_len = recvfrom(server_sock, reinterpret_cast<char*>(buffer), sizeof(buffer), 0,
                                reinterpret_cast<sockaddr*>(&client_addr), &client_len);
        if (recv_len < 0)
        {
             continue;
        }

        int offset = 12;
        std::string domain = parse_dns_name(buffer, offset, recv_len);
        std::cout << "Query: " << domain << "\n";

        int resp_len = 0;
        if (BLOCKED_DOMAINS.count(domain))
        {
            std::cout << "  → BLOCKED (NXDOMAIN)\n";
            resp_len = build_nxdomain(buffer, recv_len, response);
        } 
        else 
        {
            std::cout << "  → Forwarding to " << UPSTREAM_DNS << "\n";
            resp_len = forward_query(buffer, recv_len, response);
        }

        if (resp_len > 0)
        {
            sendto(server_sock, reinterpret_cast<const char*>(response), resp_len, 0,
            reinterpret_cast<sockaddr*>(&client_addr), client_len);
        }
    }

    closesocket(server_sock);
    restore_dns();
    WSACleanup();
    return 0;
}