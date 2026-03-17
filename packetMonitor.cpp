#include "winsock2.h"
/*
    WSAStartup() - initializes Winsock
    WSACleanup() - cleans up Winsock
    ntohs() - converts 16-bit value from network to host byte order
    ntohl() - converts 32-bit value from network to host byte order
    inet_ntop() - converts raw IP to readable string
    inet_pton() - converts readable string to raw IP
    sockaddr_in - struct for holding an IPv4 address
    WSADATA - struct required by WSAStartup
*/

#include "ws2tcpip.h"
/*
    getnameinfo() — reverse DNS lookup (IP → hostname)
    NI_MAXHOST — constant for the max hostname buffer size
    NI_NAMEREQD — flag that tells getnameinfo to only return a hostname, not fall back to the IP
*/
#include "windows.h"
/*
    SetConsoleCtrlHandler() - Windows function that registers a handler for console events (Ctrl+C)
    DWORD - Windows type for 32-bit unsigned integer
    WINAPI - Calling convention that tells the compiler how the function should be called at a low level
    CTRL_C_EVENT, CTRL_BREAK_EVENT - constants for the Ctrl+C handler
*/
#include "pcap.h"
/*
    pcap_findalldevs() — lists all network interfaces
    pcap_freealldevs() — frees the interface list
    pcap_open_live() — opens an interface for capturing
    pcap_compile() — compiles a BPF filter string
    pcap_setfilter() — applies the compiled filter
    pcap_next_ex() — gets the next packet
    pcap_close() — closes the capture handle
    pcap_geterr() — returns error message string
    pcap_stats() — returns packet capture statistics
    pcap_freecode() — frees a compiled filter
    pcap_lookupnet() — gets the network address/mask for an interface
    pcap_if_t — struct representing a network interface
    pcap_pkthdr — struct containing packet metadata (length, timestamp)
    pcap_t — the capture handle type
    bpf_program — struct for holding a compiled filter
    PCAP_ERRBUF_SIZE — constant for the error buffer size
    PCAP_ERROR — error return code constant
    u_char — unsigned char type used for raw packet data
*/

#include <iostream>
#include <iomanip>
#include <string>
#include <unordered_map>
#include <chrono>
#include <ctime>
#include <cstring>

volatile bool isRunning = true;
std::unordered_map<std::string, std::string> dnsCache;
BOOL WINAPI ctrl_c_event(DWORD event)
    {
        if (event == CTRL_C_EVENT || event == CTRL_BREAK_EVENT)
        {
            isRunning = false;
            return TRUE;
        }
        return FALSE;
    }

std::string ip_to_string(std::string ip)
{

}

int main()
{   
    SetConsoleCtrlHandler(ctrl_c_event, TRUE);

 
    return 0;
}
