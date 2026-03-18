#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <pcap/pcap.h>
#include <iostream>
#include <iomanip>
#include <string>
#include <unordered_map>
#include <unordered_set>

#pragma pack(push, 1) //Ensures that the structs are packed without padding (matches the actual packet structure)
struct EthernetHeader
{ 
        uint8_t destination[6];
        uint8_t source[6];
        uint16_t type;
};

/*
    version_ihl - version and internet header length (first 4 bits are IP version, last 4 bits are header length)
    type_of_service - type of service (used for QoS and traffic prioritization)
    total_length - total length of the IP packet (header + data)
    identification - unique identifier for the packet (used for fragmentation)
    flags_fragment_offset - flags and fragment offset (used for fragmentation)
    time_to_live - time to live (limits the packet's lifetime in the network)
    protocol - protocol type (e.g., TCP, UDP, ICMP)
    header_checksum - checksum of the IP header (used for error checking)
    source_ip - source IP address
    destination_ip - destination IP address 
    Note: The fields in the IP header are in network byte order, so they need to be converted to host byte order using ntohs() and ntohl() when processing the packet data
*/
struct IpHeader
{
        uint8_t version_ihl;
        uint8_t type_of_service;
        uint16_t total_length;
        uint16_t identification;
        uint16_t flags_fragment_offset;
        uint8_t time_to_live;
        uint8_t protocol;
        uint16_t header_checksum;
        uint32_t source_ip;
        uint32_t destination_ip;
};

struct TcpHeader
{
        uint16_t source_port;
        uint16_t destination_port;
};

struct UdpHeader
{
        uint16_t source_port;
        uint16_t destination_port;
};
#pragma pack(pop)

volatile bool is_running = true;
std::unordered_map<std::string, std::string> dns_cache;
std::unordered_set<std::string> blocked_ips;
std::unordered_set<std::string> blocked_hostnames;

/*
    BOOL - windows specific type from windows.h.Differs from bool because it is designed for C (needed because windows expects it)
    WINAPI - calling convention that tells compiler how to call function at low level
    DWORD - windows specific type for 32-bit unsigned integer
*/
BOOL WINAPI ctrl_c_event(DWORD event)
    {
        if (event == CTRL_C_EVENT || event == CTRL_BREAK_EVENT)
        {
            isRunning = false;
            std::cout << "Stopping Program" << std::endl;
            std::cout.flush();

            return TRUE;
        }
        return FALSE;
    }

/*
    in_addr - creates an in_addr struct specifically designed to hold IPv4 addresses
    [INET_ADDRSTRLEN] - constant = 16 (max length of IPv4 Address)
    AF_INET - constant for IPV4 address family
    char buf[INET_ADDRSTRLEN] - creates a character buffer to 
    buf - character array to hold string representation of IP address
    inet_ntop() - converts raw IP address to human-readable string format (needs input to be pointer to in_addr struct, outputs C string)
*/
std::string ip_to_string(uint32_t raw_ip)
{
    in_addr ip_address;
    ip_address.s_addr = raw_ip;
    char buf[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &ip_address, buf, INET_ADDRSTRLEN);

    return std::string(buf);
}

/*
    sockaddr_in - struct from winsock2 for holding IP address and port (stands for socket address internet)
    sin_family - address family (stands for socket internet family)
    inet_pton() - converts readable string to raw IP
    sin_addr - struct for holding IP address (stands for socket internet address)
    NI_NAMEREQD — flag that tells getnameinfo to only return a hostname, not fall back to the IP
    c_str() - method that returns pointer to a C string from a C++ string
    NI_MAXHOST — constant for the max hostname buffer size = 1025
    getnameinfo() — reverse DNS lookup

*/
std::string resolve_hostname(const std::string& ip_address)
{
    auto it = dns_cache.find(ip_address);
    if (it != dns_cache.end())
        return it->second;

    sockaddr_in address{};
    address.sin_family = AF_INET;
    inet_pton(AF_INET, ip_address.c_str(), &address.sin_addr);

    char buf[NI_MAXHOST];

    if (getnameinfo((sockaddr*)&address, sizeof(sockaddr_in), buf, NI_MAXHOST, nullptr, 0, 0) == 0)
        dns_cache[ip_address] = std::string(buf);
    else
        dns_cache[ip_address] = ip_address; // fall back to IP

    return dns_cache[ip_address];
}
/*
    u_char* user - pointer to unsigned char (used for raw packet data and parameters in the packet handler function)
    const struct pcap_pkthdr* header - pointer to a struct containing packet metadata (length, timestamp)
    const u_char* packet - pointer to the raw packet data
    caplen - length of the captured portion of the packet
*/
void packet_handler(u_char* user, const struct pcap_pkthdr* header, const u_char* packet)
{
    //Ensures that the captured packet is large enough to contain both an Ethernet header and an IP header (prevents out of bounds memory access)
    if(header->caplen < sizeof(EthernetHeader) + sizeof(IpHeader))
    {   
        return;
    }
    //Casts the raw packet bytes into an EthernetHeader struct so we can read its fields
    const EthernetHeader* ethernet_header = reinterpret_cast<const EthernetHeader*>(packet); 
    //ntohs() converts the Ethernet type field from network byte order to host byte order, allowing us to check if the packet is an IPv4 packet (Ethernet type 0x0800)   
    if(ntohs(ethernet_header->type) != 0x0800)
    {
        return;
    }
    //Skips first 14 bytes of the packet (size of Ethernet header) to get to the IP header, and casts it to an IpHeader struct
    const IpHeader* ip_header = reinterpret_cast<const IpHeader*>(packet + sizeof(EthernetHeader));

    //Extracts source and destination IP addresses from the IP header and converts them to readable strings
    std::string src_ip = ip_to_string(ip_header->source_ip); 
    std::string dest_ip = ip_to_string(ip_header->destination_ip);

    // If IP already blocked, discard immediately
    if (blocked_ips.count(src_ip))
    {
        return;
    }

    std::string src_hostname = resolve_hostname(src_ip);

    for (const std::string& keyword : blocked_hostnames)
    {
        if (src_hostname.find(keyword) != std::string::npos)
        {
            std::cout << "Blocking " << src_ip << " (" << src_hostname << ") - matched: " << keyword << "\n";
            blocked_ips.insert(src_ip);
            return;
        }
    }

    //Extracts the protocol number (TCP, UDP, etc) from the IP header
    uint8_t protocol = ip_header->protocol; 

    //Calculates the IP header length by masking the lower 4 bits of version_ihl and multiplying by 4 (converts 32-bit words to bytes)
    uint8_t ip_header_length = (ip_header->version_ihl & 0x0F) * 4;

    //Calculates a pointer to the start of the transport layer (TCP/UDP) header by skipping past the Ethernet and IP headers
    const u_char* transport = packet + sizeof(EthernetHeader) + ip_header_length;
    uint16_t src_port = 0;
    uint16_t dst_port = 0;
    if(protocol == IPPROTO_TCP)
    {
        //Ensures the packet is large enough to contain a TCP header
        if(header->caplen < sizeof(EthernetHeader) + ip_header_length + sizeof(TcpHeader))
        {
            return;
        }
        //Casts the transport layer bytes into a TcpHeader struct so we can read the source and destination ports
        const TcpHeader* tcp_header = reinterpret_cast<const TcpHeader*>(transport);
        src_port = ntohs(tcp_header->source_port);
        dst_port = ntohs(tcp_header->destination_port);
    }
    else if(protocol == IPPROTO_UDP)
    {   
        //Ensures the packet is large enough to contain a UDP header
        if(header->caplen < sizeof(EthernetHeader) + ip_header_length + sizeof(UdpHeader))
        {
            return;
        }
        const UdpHeader* udp_header = reinterpret_cast<const UdpHeader*>(transport);
        src_port = ntohs(udp_header->source_port);
        dst_port = ntohs(udp_header->destination_port);
    }

    std::cout << (int)protocol << " | " << src_ip << " | " << src_port << " | " << src_hostname << std::endl; 
    std::cout.flush();
}

int main()
{   
    std::cout << "Program Start:\n";
    //WSADATA - struct required by WSAStartup
    WSAData wsa_data;

    //Initializes Winsock
    std::cout << "Initializing Winsock:\n";
    WSAStartup(MAKEWORD(2, 2), &wsa_data);

    std::cout << "Setting Ctrl-C Handler:\n";
    SetConsoleCtrlHandler(ctrl_c_event, TRUE);

    //PCAP_ERRBUF_SIZE — constant for the error buffer size
    char error_buffer[PCAP_ERRBUF_SIZE];

    //pcap_if_t — struct that represents network interface
    pcap_if_t* all_interfaces = nullptr;
    
    //pcap_findalldevs() — lists all network interfaces
    std::cout << "Finding Interfaces:\n";
    if(pcap_findalldevs(&all_interfaces, error_buffer) == -1 || all_interfaces == nullptr)
    {
        std::cerr << "Error finding interfaces: " << error_buffer << "\n";
        return 1;
    }
    
    // Print all interfaces
    pcap_if_t* dev = all_interfaces;
    int i = 0;
    while (dev)
    {
        std::cout << i++ << ": " << dev->name;
        if (dev->description) std::cout << " (" << dev->description << ")";
        std::cout << "\n";
        dev = dev->next;
    }

    int choice = 0;
    std::cout << "Select interface number: ";
    std::cin >> choice;

    pcap_if_t* selected = all_interfaces;
    for (int j = 0; j < choice && selected != nullptr; j++)
        selected = selected->next;

    if (selected == nullptr)
    {
        std::cerr << "Invalid selection\n";
        return 1;
    }
    std::cout << "Selected: " << selected->name << "\n";
    //pcap_t — capture handle type
    pcap_t* handle = nullptr;
    int snaplen = 65536; //max bytes to capture per packet
    //pcap_open_live() — opens an interface for capturing
    handle = pcap_open_live(selected->name, snaplen, 0, 1000, error_buffer);
    if(handle == nullptr)
    {
        std::cerr << "Error opening interface: " << error_buffer << "\n";
        return 1;
    }

    //bpf_program — struct for holding a compiled filter
    bpf_program filter;

    //pcap_compile() — compiles a BPF filter string
    pcap_compile(handle, &filter, "ip", 1, PCAP_NETMASK_UNKNOWN);

    //pcap_setfilter() — applies the compiled filter
    pcap_setfilter(handle, &filter);

    pcap_pkthdr* packet_header = nullptr;
    const u_char* packet_data = nullptr;

    std::cout << "Starting Packet Capture:\n";
    int packet_count = 0;
    while(is_running)
    {
        //pcap_next_ex() — gets the next packet
        if(pcap_next_ex(handle, &packet_header, &packet_data) == 1)
        {
            packet_handler(nullptr, packet_header, packet_data);
            packet_count++;
        }
    }

    //pcap_freecode() — frees a compiled filter
    std::cout << "Cleaning Up:\n";
    pcap_freecode(&filter);

    //pcap_close() — closes the capture handle
    std::cout << "Closing Capture Handle:\n";
    pcap_close(handle);

    //pcap_freealldevs() — frees the interface list
    std::cout << "Freeing Interface List:\n";
    pcap_freealldevs(all_interfaces);

    //Cleans up Winsock
    std::cout << "Cleaning up Winsock:\n";
    WSACleanup();
    return 0;
}
