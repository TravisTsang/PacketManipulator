/*
PROGRAM STRUCTURE:
    1. Open network interface with pcap
    2. Capture every packet passing through
    3. If packet is UDP from port 53 (DNS response):
        - parse domain name and resolved IP from packet
        - if domain matches blocklist:
            - add resolved IP to blocked list
            - call WFP to block that IP at kernel level
    4. If packet is from already blocked IP:
        - discard immediately

Problem: Modern browsers use DNS over HTTPS (DoH), which encrypts DNS queries, making it impossible to read domain names without decryption
*/

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <pcap/pcap.h>
#include <fwpmu.h>
#include <iostream>
#include <iomanip>
#include <string>
#include <unordered_map>
#include <unordered_set>

#pragma pack(push, 1)
struct EthernetHeader
{ 
    uint8_t destination[6];
    uint8_t source[6];
    uint16_t type;
};

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
    uint16_t length;
    uint16_t checksum;
};

/*
    transaction_id - unique ID to match a DNS query to its response
    flags - QR bit (bit 15) tells you if packet is a query (0) or response (1)
    question_count - number of questions in the packet
    answer_count - number of answers in the packet (only in responses)
    authority_count - number of authority records
    additional_count - number of additional records
*/
struct DnsHeader
{
    uint16_t transaction_id;
    uint16_t flags;
    uint16_t question_count;
    uint16_t answer_count;
    uint16_t authority_count;
    uint16_t additional_count;
};
#pragma pack(pop)

volatile bool is_running = true;
std::unordered_set<std::string> blocked_ips;
std::unordered_set<std::string> blocked_hostnames =
{
    "youtube.com",
    "googlevideo.com",
    "gvt1.com",
    "1e100.net"
};

HANDLE wfp_engine = nullptr;
static const GUID FWPM_CONDITION_IP_REMOTE_ADDRESS = {0x4cd62a49, 0x59c3, 0x4969, {0xb7, 0xf3, 0xbd, 0xa5, 0xd3, 0x28, 0x90, 0xa4}};
static const GUID FWPM_LAYER_ALE_AUTH_CONNECT_V4 = {0xc38d57d1, 0x05a7, 0x4c33, {0x90, 0x4f, 0x7f, 0xbc, 0xee, 0xe6, 0x0e, 0x82}};
#define FWPM_SESSION_FLAG_DYNAMIC 0x00000001

BOOL WINAPI ctrl_c_event(DWORD event)
{
    if (event == CTRL_C_EVENT || event == CTRL_BREAK_EVENT)
    {
        is_running = false;
        std::cout << "Stopping Program" << std::endl;
        std::cout.flush();
        return TRUE;
    }
    return FALSE;
}

std::string ip_to_string(uint32_t raw_ip)
{
    in_addr ip_address;
    ip_address.s_addr = raw_ip;
    char buf[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &ip_address, buf, INET_ADDRSTRLEN);
    return std::string(buf);
}

void block_ip(const std::string& ip_str)
{
    FWPM_FILTER0 filter = {};
    FWPM_FILTER_CONDITION0 condition = {};
    FWP_V4_ADDR_AND_MASK_ address = {};

    IN_ADDR address_in;
    inet_pton(AF_INET, ip_str.c_str(), &address_in);
    address.addr = ntohl(address_in.s_addr);
    address.mask = 0xFFFFFFFF;

    condition.fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS;
    condition.matchType = FWP_MATCH_EQUAL;
    condition.conditionValue.type = FWP_V4_ADDR_MASK;
    condition.conditionValue.v4AddrMask = &address;

    filter.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V4;
    filter.action.type = FWP_ACTION_BLOCK;
    filter.filterCondition = &condition;
    filter.numFilterConditions = 1;
    filter.weight.type = FWP_EMPTY;
    filter.displayData.name = const_cast<wchar_t*>(L"Packet Monitor Block");

    UINT64 filter_id = 0;
    FwpmFilterAdd0(wfp_engine, &filter, nullptr, &filter_id);
    std::cout << "Blocking IP: " << ip_str << "\n";
    std::cout.flush();
}

/*
    Parses a DNS name from the packet which uses label encoding format
    e.g. \x07youtube\x03com\x00 → "youtube.com"
    data - pointer to start of the entire DNS payload (needed for pointer compression)
    offset - current position in the DNS payload where the name starts
    dns_len - total length of DNS payload (used to prevent out of bounds reads)
    Each label is preceded by its length byte, ending with a 0x00 byte
    0xC0 prefix means compression pointer — the name continues at another offset
*/
std::string parse_dns_name(const u_char* data, int offset, int dns_len)
{
    std::string name;
    int max_jumps = 10; // prevents infinite loops from malformed packets
    bool jumped = false;

    while (offset < dns_len)
    {
        uint8_t len = data[offset];

        // 0x00 means end of name
        if (len == 0)
            break;

        // 0xC0 prefix means this is a compression pointer — jump to another offset
        if ((len & 0xC0) == 0xC0)
        {
            if (offset + 1 >= dns_len) break;
            int pointer = ((len & 0x3F) << 8) | data[offset + 1];
            offset = pointer;
            if (--max_jumps == 0) break; // malformed packet guard
            jumped = true;
            continue;
        }

        offset++;
        if (!name.empty()) name += ".";

        // Read 'len' characters as the next label
        for (int i = 0; i < len && offset < dns_len; i++, offset++)
            name += (char)data[offset];
    }

    return name;
}

/*
    Parses a DNS response packet to extract domain names and their resolved IPs
    dns_data - pointer to the start of the DNS payload (after UDP header)
    dns_len - length of the DNS payload
    Checks the QR bit in flags to confirm it's a response (QR = 1)
    Skips over the question section to reach the answer section
    Each answer record contains: name, type, class, TTL, data length, and data
    Type 1 (A record) contains an IPv4 address in the data field
*/
void parse_dns_response(const u_char* dns_data, int dns_len)
{
    if (dns_len < (int)sizeof(DnsHeader)) return;

    const DnsHeader* dns_header = reinterpret_cast<const DnsHeader*>(dns_data);

    // Check QR bit (bit 15 of flags) — must be 1 for a response
    if (!(ntohs(dns_header->flags) & 0x8000)) return;

    int question_count = ntohs(dns_header->question_count);
    int answer_count = ntohs(dns_header->answer_count);

    if (answer_count == 0) return;

    // Start reading after the DNS header
    int offset = sizeof(DnsHeader);

    // Skip over all questions to reach the answers
    for (int i = 0; i < question_count; i++)
    {
        // Skip the name
        while (offset < dns_len)
        {
            uint8_t len = dns_data[offset];
            if (len == 0) { offset++; break; }
            if ((len & 0xC0) == 0xC0) { offset += 2; break; } // compression pointer
            offset += len + 1;
        }
        offset += 4; // skip type (2 bytes) and class (2 bytes)
    }

    // Parse each answer record
    for (int i = 0; i < answer_count; i++)
    {
        if (offset >= dns_len) break;

        // Parse the name this answer is for
        std::string name = parse_dns_name(dns_data, offset, dns_len);

        // Skip the name field
        while (offset < dns_len)
        {
            uint8_t len = dns_data[offset];
            if (len == 0) { offset++; break; }
            if ((len & 0xC0) == 0xC0) { offset += 2; break; }
            offset += len + 1;
        }

        if (offset + 10 > dns_len) break;

        uint16_t type = ntohs(*reinterpret_cast<const uint16_t*>(dns_data + offset));
        offset += 2; // type
        offset += 2; // class
        offset += 4; // TTL
        uint16_t data_len = ntohs(*reinterpret_cast<const uint16_t*>(dns_data + offset));
        offset += 2; // data length

        // Type 1 = A record (IPv4 address)
        if (type == 1 && data_len == 4 && offset + 4 <= dns_len)
        {
            // Extract the resolved IP from the answer
            uint32_t raw_ip;
            memcpy(&raw_ip, dns_data + offset, 4);
            std::string resolved_ip = ip_to_string(raw_ip);

            // Check if the domain matches any blocked hostname
            for (const std::string& keyword : blocked_hostnames)
            {
                if (name.find(keyword) != std::string::npos)
                {
                    std::cout << "DNS: " << name << " -> " << resolved_ip << " (blocked)\n";
                    std::cout.flush();
                    if (!blocked_ips.count(resolved_ip))
                    {
                        blocked_ips.insert(resolved_ip);
                        block_ip(resolved_ip);
                    }
                    break;
                }
            }
        }

        offset += data_len;
    }
}

void packet_handler(u_char* user, const struct pcap_pkthdr* header, const u_char* packet)
{
    if (header->caplen < sizeof(EthernetHeader) + sizeof(IpHeader))
        return;

    const EthernetHeader* ethernet_header = reinterpret_cast<const EthernetHeader*>(packet);
    if (ntohs(ethernet_header->type) != 0x0800)
        return;

    const IpHeader* ip_header = reinterpret_cast<const IpHeader*>(packet + sizeof(EthernetHeader));
    uint8_t protocol = ip_header->protocol;
    uint8_t ip_header_length = (ip_header->version_ihl & 0x0F) * 4;
    const u_char* transport = packet + sizeof(EthernetHeader) + ip_header_length;

    std::string src_ip = ip_to_string(ip_header->source_ip);
    std::string dest_ip = ip_to_string(ip_header->destination_ip);

    if (blocked_ips.count(src_ip))
        return;

    uint16_t src_port = 0;
    uint16_t dst_port = 0;

    if (protocol == IPPROTO_UDP)
    {
        if (header->caplen < sizeof(EthernetHeader) + ip_header_length + sizeof(UdpHeader))
            return;

        const UdpHeader* udp_header = reinterpret_cast<const UdpHeader*>(transport);
        src_port = ntohs(udp_header->source_port);
        dst_port = ntohs(udp_header->destination_port);

        if (src_port == 53)
        {
            // Debug line in the right place
            std::cout << "DNS response seen from " << src_ip << "\n";
            std::cout.flush();

            const u_char* dns_data = transport + sizeof(UdpHeader);
            int dns_len = header->caplen - sizeof(EthernetHeader) - ip_header_length - sizeof(UdpHeader);
            parse_dns_response(dns_data, dns_len);
            return;
        }
    }
    else if (protocol == IPPROTO_TCP)
    {
        if (header->caplen < sizeof(EthernetHeader) + ip_header_length + sizeof(TcpHeader))
            return;

        const TcpHeader* tcp_header = reinterpret_cast<const TcpHeader*>(transport);
        src_port = ntohs(tcp_header->source_port);
        dst_port = ntohs(tcp_header->destination_port);
    }

    std::cout << (int)protocol << " | " << src_ip << " | " << src_port << " | " << dest_ip << "\n";
    std::cout.flush();
}

int main()
{   
    std::cout << "Program Start:\n";
    WSAData wsa_data;

    FWPM_SESSION0 session = {};
    session.flags = FWPM_SESSION_FLAG_DYNAMIC;
    FwpmEngineOpen0(nullptr, RPC_C_AUTHN_WINNT, nullptr, &session, &wfp_engine);

    std::cout << "Initializing Winsock:\n";
    WSAStartup(MAKEWORD(2, 2), &wsa_data);

    std::cout << "Setting Ctrl-C Handler:\n";
    SetConsoleCtrlHandler(ctrl_c_event, TRUE);

    char error_buffer[PCAP_ERRBUF_SIZE];
    pcap_if_t* all_interfaces = nullptr;
    
    std::cout << "Finding Interfaces:\n";
    if (pcap_findalldevs(&all_interfaces, error_buffer) == -1 || all_interfaces == nullptr)
    {
        std::cerr << "Error finding interfaces: " << error_buffer << "\n";
        return 1;
    }
    
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

    pcap_t* handle = nullptr;
    int snaplen = 65536;
    handle = pcap_open_live(selected->name, snaplen, 0, 1000, error_buffer);
    if (handle == nullptr)
    {
        std::cerr << "Error opening interface: " << error_buffer << "\n";
        return 1;
    }

    bpf_program filter;
    pcap_compile(handle, &filter, "ip", 1, PCAP_NETMASK_UNKNOWN);
    pcap_setfilter(handle, &filter);

    pcap_pkthdr* packet_header = nullptr;
    const u_char* packet_data = nullptr;

    std::cout << "Starting Packet Capture:\n";
    while (is_running)
    {
        if (pcap_next_ex(handle, &packet_header, &packet_data) == 1)
            packet_handler(nullptr, packet_header, packet_data);
    }

    std::cout << "Cleaning Up:\n";
    pcap_freecode(&filter);
    pcap_close(handle);
    pcap_freealldevs(all_interfaces);
    WSACleanup();
    FwpmEngineClose0(wfp_engine);
    return 0;
}