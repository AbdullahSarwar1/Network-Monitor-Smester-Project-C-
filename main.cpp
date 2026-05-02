#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

#include <pcap.h>
#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <map>
#include <mutex>
#include <thread>
#include <atomic>
#include <chrono>
#include <ctime>
#include <cstring>
#include <algorithm>
#include <exception>
#include <iomanip>
#include <cstdio>

using namespace std;

#pragma comment(lib, "wpcap.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "Packet.lib")

// Packet Headers

#pragma pack(push, 1)
struct EtherHeader
{
    uint8_t dest[6];
    uint8_t src[6];
    uint16_t type;
};

struct IpHeader
{
    uint8_t ver_ihl;
    uint8_t tos;
    uint16_t total_len;
    uint16_t id;
    uint16_t flags_frag;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t checksum;
    uint32_t src_addr;
    uint32_t dst_addr;
};

struct TcpHeader
{
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq;
    uint32_t ack;
    uint8_t data_off;
    uint8_t flags;
    uint16_t window;
    uint16_t checksum;
    uint16_t urg_ptr;
};

struct UdpHeader
{
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t length;
    uint16_t checksum;
};

struct IcmpHeader
{
    uint8_t type;
    uint8_t code;
    uint16_t checksum;
    uint32_t rest;
};

struct Ipv6Header
{
    uint32_t ver_tc_fl; // Version(4), Traffic Class(8), Flow Label(20)
    uint16_t payload_len;
    uint8_t next_header;
    uint8_t hop_limit;
    uint8_t src_addr[16];
    uint8_t dst_addr[16];
};
#pragma pack(pop)

// Packet Record

struct PacketRecord
{
    string time_str;
    string src_ip;
    string dst_ip;
    string protocol;
    int packet_size;
    int src_port;
    int dst_port;
    string service;
};

// Globals

vector<PacketRecord> g_packets;
mutex g_mutex;
atomic<bool> g_capturing(false);
atomic<long long> g_total_bytes(0);
pcap_t *g_handle = nullptr;
thread g_capture_thread;

// Rate limiting
atomic<int> g_packets_this_sec(0);
atomic<int> g_max_pps(1000); // Max packets per second to prevent UI overwhelm

// Stats

map<string, int> g_proto_count;
map<string, int> g_service_count;

// Helpers

string get_time_str()
{
    auto now = chrono::system_clock::now();
    time_t t = chrono::system_clock::to_time_t(now);
    struct tm tm_info;
    localtime_s(&tm_info, &t);
    char buf[32];
    strftime(buf, sizeof(buf), "%I:%M:%S %p", &tm_info);
    return string(buf);
}

string ip_to_str(uint32_t ip)
{
    struct in_addr addr;
    addr.s_addr = ip;
    char buf[INET_ADDRSTRLEN];
    if (!inet_ntop(AF_INET, &addr, buf, sizeof(buf)))
        return "0.0.0.0";
    return string(buf);
}

string ipv6_to_str(const uint8_t *ip)
{
    char buf[INET6_ADDRSTRLEN];
    if (!inet_ntop(AF_INET6, ip, buf, sizeof(buf)))
        return "::";
    return string(buf);
}

string port_to_service(int port)
{
    static const map<int, string> services = {
        {20, "FTP-Data"}, {21, "FTP"}, {22, "SSH"}, {23, "Telnet"}, {25, "SMTP"}, {53, "DNS"}, {67, "DHCP"}, {68, "DHCP"}, {69, "TFTP"}, {80, "HTTP"}, {110, "POP3"}, {119, "NNTP"}, {123, "NTP"}, {143, "IMAP"}, {161, "SNMP"}, {194, "IRC"}, {443, "HTTPS"}, {465, "SMTPS"}, {514, "Syslog"}, {587, "SMTP-Sub"}, {993, "IMAPS"}, {995, "POP3S"}, {1080, "SOCKS"}, {1194, "OpenVPN"}, {1433, "MSSQL"}, {1521, "Oracle-DB"}, {3306, "MySQL"}, {3389, "RDP"}, {5432, "PostgreSQL"}, {5900, "VNC"}, {6379, "Redis"}, {8080, "HTTP-Alt"}, {8443, "HTTPS-Alt"}, {27017, "MongoDB"}};
    auto it = services.find(port);
    if (it != services.end())
        return it->second;
    if (port == 0)
        return "-";
    return "Unknown";
}

string escape_json(const string &s)
{
    string out;
    for (unsigned char c : s)
    {
        switch (c)
        {
        case '"':
            out += "\\\"";
            break;
        case '\\':
            out += "\\\\";
            break;
        case '\b':
            out += "\\b";
            break;
        case '\f':
            out += "\\f";
            break;
        case '\n':
            out += "\\n";
            break;
        case '\r':
            out += "\\r";
            break;
        case '\t':
            out += "\\t";
            break;
        default:
            // Escape control characters (0x00-0x1F)
            if (c < 0x20)
            {
                char buf[7];
                snprintf(buf, sizeof(buf), "\\u%04x", c);
                out += buf;
            }
            else
            {
                out += c;
            }
        }
    }
    return out;
}

// Packet Handler

void packet_handler(u_char * /*user*/, const struct pcap_pkthdr *hdr, const u_char *pkt)
{
    if (!g_capturing)
        return;

    if (hdr->caplen < sizeof(EtherHeader))
        return;

    const EtherHeader *eth = reinterpret_cast<const EtherHeader *>(pkt);
    uint16_t eth_type = ntohs(eth->type);

    // Handle IPv4 (0x0800) and IPv6 (0x86DD)
    PacketRecord rec;
    rec.time_str = get_time_str();
    rec.src_port = 0;
    rec.dst_port = 0;
    uint8_t protocol = 0;
    const u_char *transport = nullptr;

    if (eth_type == 0x0800)
    { // IPv4
        if (hdr->caplen < sizeof(EtherHeader) + sizeof(IpHeader))
            return;

        const IpHeader *ip = reinterpret_cast<const IpHeader *>(pkt + sizeof(EtherHeader));
        int ip_hlen = (ip->ver_ihl & 0x0F) * 4;
        // Validate IP header length (minimum 20 bytes, max 60 bytes)
        if (ip_hlen < 20 || ip_hlen > 60)
            return;

        rec.src_ip = ip_to_str(ip->src_addr);
        rec.dst_ip = ip_to_str(ip->dst_addr);
        rec.packet_size = ntohs(ip->total_len);
        protocol = ip->protocol;
        transport = pkt + sizeof(EtherHeader) + ip_hlen;
    }
    else if (eth_type == 0x86DD)
    { // IPv6
        if (hdr->caplen < sizeof(EtherHeader) + sizeof(Ipv6Header))
            return;

        const Ipv6Header *ip6 = reinterpret_cast<const Ipv6Header *>(pkt + sizeof(EtherHeader));
        rec.src_ip = ipv6_to_str(ip6->src_addr);
        rec.dst_ip = ipv6_to_str(ip6->dst_addr);
        rec.packet_size = ntohs(ip6->payload_len) + sizeof(Ipv6Header);
        protocol = ip6->next_header;
        transport = pkt + sizeof(EtherHeader) + sizeof(Ipv6Header);
    }
    else
    {
        return; // Not IP
    }

    // Ensure transport layer is within captured packet
    if (transport >= pkt + hdr->caplen)
        return;

    switch (protocol)
    {
    case 6:
    { // TCP
        rec.protocol = "TCP";
        if (hdr->caplen >= static_cast<size_t>(transport - pkt) + sizeof(TcpHeader))
        {
            const TcpHeader *tcp = reinterpret_cast<const TcpHeader *>(transport);
            rec.src_port = ntohs(tcp->src_port);
            rec.dst_port = ntohs(tcp->dst_port);
        }
        break;
    }
    case 17:
    { // UDP
        rec.protocol = "UDP";
        if (hdr->caplen >= static_cast<size_t>(transport - pkt) + sizeof(UdpHeader))
        {
            const UdpHeader *udp = reinterpret_cast<const UdpHeader *>(transport);
            rec.src_port = ntohs(udp->src_port);
            rec.dst_port = ntohs(udp->dst_port);
        }
        break;
    }
    case 1:  // ICMP (IPv4)
    case 58: // ICMPv6
        rec.protocol = "ICMP";
        // ICMP has type/code instead of ports - show type in src_port
        if (hdr->caplen >= static_cast<size_t>(transport - pkt) + sizeof(IcmpHeader)) {
            const IcmpHeader *icmp = reinterpret_cast<const IcmpHeader *>(transport);
            rec.src_port = icmp->type;   // ICMP Type
            rec.dst_port = icmp->code;   // ICMP Code
        }
        break;
    default:
        rec.protocol = "OTHER";
        break;
    }

    // Map service from destination port (well-known) or source port
    // Skip service lookup for ICMP (type/code are not ports)
    if (rec.protocol == "ICMP") {
        rec.service = "-";
    } else {
        rec.service = port_to_service(rec.dst_port);
        if (rec.service == "Unknown" || rec.service == "-")
            rec.service = port_to_service(rec.src_port);
    }

    // Rate limiting check
    if (g_packets_this_sec.fetch_add(1) >= g_max_pps.load())
    {
        g_packets_this_sec.fetch_sub(1);
        return; // Drop packet due to rate limiting
    }

    {
        lock_guard<mutex> lock(g_mutex);
        // Prevent memory exhaustion - keep max 10000 packets
        if (g_packets.size() >= 10000)
        {
            g_total_bytes -= g_packets.front().packet_size;
            g_packets.erase(g_packets.begin());
        }
        g_packets.push_back(rec);
        g_proto_count[rec.protocol]++;
        g_service_count[rec.service]++;
        g_total_bytes += rec.packet_size;
    }
}

// Capture Thread

void capture_loop(const string &dev_name)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    g_handle = pcap_open_live(dev_name.c_str(), 65535, 1, 1000, errbuf);
    if (!g_handle)
    {
        cerr << "[ERROR] pcap_open_live: " << errbuf << "\n";
        lock_guard<mutex> lock(g_mutex);
        g_capturing = false;
        return;
    }

    // Capture both IPv4 and IPv6 packets
    struct bpf_program fp;
    if (pcap_compile(g_handle, &fp, "ip or ip6", 0, PCAP_NETMASK_UNKNOWN) == 0)
    {
        pcap_setfilter(g_handle, &fp);
        pcap_freecode(&fp);
    }

    // Reset packet counter every second for rate limiting
    auto last_reset = chrono::steady_clock::now();

    while (g_capturing)
    {
        pcap_dispatch(g_handle, 100, packet_handler, nullptr);

        // Reset rate limit counter every second
        auto now = chrono::steady_clock::now();
        if (chrono::duration_cast<chrono::seconds>(now - last_reset).count() >= 1)
        {
            g_packets_this_sec.store(0);
            last_reset = now;
        }
    }

    pcap_close(g_handle);
    g_handle = nullptr;
}

// HTTP Server

string list_devices_json()
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevs;
    string json = "[";
    if (pcap_findalldevs(&alldevs, errbuf) == -1)
    {
        return "[]";
    }
    bool first = true;
    for (pcap_if_t *d = alldevs; d; d = d->next)
    {
        if (!first)
            json += ",";
        first = false;
        string name = d->name ? d->name : "";
        string desc = d->description ? d->description : name;
        json += "{\"name\":\"" + escape_json(name) + "\",\"desc\":\"" + escape_json(desc) + "\"}";
    }
    json += "]";
    pcap_freealldevs(alldevs);
    return json;
}

string packets_to_json(const string &filter_proto,
                       const string &filter_src,
                       const string &filter_dst)
{
    lock_guard<mutex> lock(g_mutex);
    string json = "[";
    bool first = true;
    for (const auto &p : g_packets)
    {
        if (!filter_proto.empty() && filter_proto != "ALL" && p.protocol != filter_proto)
            continue;
        if (!filter_src.empty() && p.src_ip.find(filter_src) == string::npos)
            continue;
        if (!filter_dst.empty() && p.dst_ip.find(filter_dst) == string::npos)
            continue;
        if (!first)
            json += ",";
        first = false;
        json += "{";
        json += "\"time\":\"" + escape_json(p.time_str) + "\",";
        json += "\"src_ip\":\"" + escape_json(p.src_ip) + "\",";
        json += "\"dst_ip\":\"" + escape_json(p.dst_ip) + "\",";
        json += "\"protocol\":\"" + escape_json(p.protocol) + "\",";
        json += "\"size\":" + to_string(p.packet_size) + ",";
        json += "\"src_port\":" + to_string(p.src_port) + ",";
        json += "\"dst_port\":" + to_string(p.dst_port) + ",";
        json += "\"service\":\"" + escape_json(p.service) + "\"";
        json += "}";
    }
    json += "]";
    return json;
}

string stats_to_json()
{
    lock_guard<mutex> lock(g_mutex);
    int total = (int)g_packets.size();
    long long bytes = g_total_bytes.load();
    double avg_size = total > 0 ? (double)bytes / total : 0.0;

    // Format avg_size with 2 decimal places using ostringstream
    ostringstream avg_stream;
    avg_stream << fixed << setprecision(2) << avg_size;

    string json = "{";
    json += "\"total\":" + to_string(total) + ",";
    json += "\"total_bytes\":" + to_string(bytes) + ",";
    json += "\"avg_size\":" + avg_stream.str() + ",";
    json += "\"proto\":{";
    bool first = true;
    for (auto &kv : g_proto_count)
    {
        if (!first)
            json += ",";
        first = false;
        json += "\"" + kv.first + "\":" + to_string(kv.second);
    }
    json += "},\"services\":{";
    first = true;
    int count = 0;
    for (auto &kv : g_service_count)
    {
        if (count++ >= 10)
            break;
        if (!first)
            json += ",";
        first = false;
        json += "\"" + escape_json(kv.first) + "\":" + to_string(kv.second);
    }
    json += "}}";
    return json;
}

// Read any file into string
string read_file(const string &path)
{
    ifstream f(path, ios::binary);
    if (!f.is_open())
        return "";
    stringstream ss;
    ss << f.rdbuf();
    return ss.str();
}

// Serve the index.html file
string read_html_file()
{
    string content = read_file("../web/index.html");
    if (content.empty())
        content = read_file("web/index.html");
    if (content.empty())
        content = read_file("index.html");
    if (content.empty())
        return "<h1>index.html not found</h1>";
    return content;
}

// Serve static files (CSS, JS)
string serve_static(const string &filename, string &content_type)
{
    string content;
    // Try multiple paths
    content = read_file("../web/" + filename);
    if (content.empty())
        content = read_file("web/" + filename);
    if (content.empty())
        content = read_file(filename);

    if (content.empty())
    {
        content_type = "";
        return "";
    }

    // Set content type based on extension
    if (filename.find(".css") != string::npos)
    {
        content_type = "text/css";
    }
    else if (filename.find(".js") != string::npos)
    {
        content_type = "application/javascript";
    }
    else
    {
        content_type = "text/plain";
    }
    return content;
}

void handle_client(SOCKET client)
{
    // Read HTTP request with size limit to prevent overflow
    string req;
    char buf[4096];
    int total_len = 0;
    const int MAX_REQ_SIZE = 8192; // Max request size limit

    while (total_len < MAX_REQ_SIZE)
    {
        int len = recv(client, buf, min((int)sizeof(buf), MAX_REQ_SIZE - total_len), 0);
        if (len <= 0)
            break;
        req.append(buf, len);
        total_len += len;

        // Check if we have complete HTTP headers (end with \r\n\r\n)
        if (req.find("\r\n\r\n") != string::npos)
            break;
    }

    if (req.empty())
    {
        closesocket(client);
        return;
    }
    string method, path;
    istringstream ss(req);
    ss >> method >> path;

    // Parse query string
    string query;
    auto qpos = path.find('?');
    if (qpos != string::npos)
    {
        query = path.substr(qpos + 1);
        path = path.substr(0, qpos);
    }

    auto get_param = [&](const string &key) -> string
    {
        string search = key + "=";
        auto pos = query.find(search);
        if (pos == string::npos)
            return "";
        pos += search.size();
        auto end = query.find('&', pos);
        string val = (end == string::npos) ? query.substr(pos) : query.substr(pos, end - pos);
        // URL decode basic
        string decoded;
        for (size_t i = 0; i < val.size(); ++i)
        {
            if (val[i] == '+')
                decoded += ' ';
            else if (val[i] == '%' && i + 2 < val.size())
            {
                int hex;
                sscanf_s(val.c_str() + i + 1, "%2x", &hex);
                decoded += (char)hex;
                i += 2;
            }
            else
                decoded += val[i];
        }
        return decoded;
    };

    string body, content_type;

    if (path == "/" || path == "/index.html")
    {
        body = read_html_file();
        content_type = "text/html";
    }
    else if (path == "/api/devices")
    {
        body = list_devices_json();
        content_type = "application/json";
    }
    else if (path == "/api/start")
    {
        string dev = get_param("device");
        if (!dev.empty() && !g_capturing)
        {
            {
                lock_guard<mutex> lock(g_mutex);
                g_packets.clear();
                g_proto_count.clear();
                g_service_count.clear();
                g_total_bytes = 0;
            }
            g_capturing = true;
            try
            {
                g_capture_thread = thread(capture_loop, dev);
                g_capture_thread.detach();
            }
            catch (const exception &e)
            {
                lock_guard<mutex> lock(g_mutex);
                g_capturing = false;
                body = "{\"status\":\"error\",\"msg\":\"Failed to start capture thread: " +
                       escape_json(e.what()) + "\"}";
                content_type = "application/json";
                goto send_response;
            }
            body = "{\"status\":\"started\",\"device\":\"" + escape_json(dev) + "\"}";
        }
        else if (g_capturing)
        {
            body = "{\"status\":\"already_running\"}";
        }
        else
        {
            body = "{\"status\":\"error\",\"msg\":\"No device specified\"}";
        }
        content_type = "application/json";
    }
    else if (path == "/api/stop")
    {
        g_capturing = false;
        body = "{\"status\":\"stopped\"}";
        content_type = "application/json";
    }
    else if (path == "/api/packets")
    {
        body = packets_to_json(get_param("proto"), get_param("src"), get_param("dst"));
        content_type = "application/json";
    }
    else if (path == "/api/stats")
    {
        body = stats_to_json();
        content_type = "application/json";
    }
    else if (path == "/api/export")
    {
        // Export CSV log - send as downloadable file
        lock_guard<mutex> lock(g_mutex);
        body = "Time,Source IP,Destination IP,Protocol,Packet Size,Src Port,Dst Port,Service\n";
        for (auto &p : g_packets)
        {
            // Escape fields that might contain commas
            string safe_src_ip = p.src_ip.find(',') != string::npos ? "\"" + p.src_ip + "\"" : p.src_ip;
            string safe_dst_ip = p.dst_ip.find(',') != string::npos ? "\"" + p.dst_ip + "\"" : p.dst_ip;
            string safe_service = p.service.find(',') != string::npos ? "\"" + p.service + "\"" : p.service;
            body += p.time_str + "," + safe_src_ip + "," + safe_dst_ip + "," + p.protocol + "," + to_string(p.packet_size) + "," + to_string(p.src_port) + "," + to_string(p.dst_port) + "," + safe_service + "\n";
        }
        content_type = "text/csv";
    }
    else if (path == "/api/status")
    {
        body = string("{\"capturing\":") + (g_capturing ? "true" : "false") +
               ",\"packets\":" + to_string(g_packets.size()) + "}";
        content_type = "application/json";
    }
    else if (path == "/style.css")
    {
        body = serve_static("style.css", content_type);
        if (content_type.empty())
        {
            body = "{\"error\":\"not found\"}";
            content_type = "application/json";
        }
    }
    else if (path == "/script.js")
    {
        body = serve_static("script.js", content_type);
        if (content_type.empty())
        {
            body = "{\"error\":\"not found\"}";
            content_type = "application/json";
        }
    }
    else
    {
        body = "{\"error\":\"not found\"}";
        content_type = "application/json";
    }

send_response:
    string response =
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: " +
        content_type + "; charset=utf-8\r\n"
                       "Access-Control-Allow-Origin: *\r\n";

    // Add download header for CSV export
    if (content_type == "text/csv")
    {
        response += "Content-Disposition: attachment; filename=\"capture_log.csv\"\r\n";
    }

    response += "Content-Length: " + to_string(body.size()) + "\r\n"
                                                              "Connection: close\r\n\r\n" +
                body;

    send(client, response.c_str(), (int)response.size(), 0);
    closesocket(client);
}

int main()
{
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);

    SOCKET server = socket(AF_INET, SOCK_STREAM, 0);
    int opt = 1;
    setsockopt(server, SOL_SOCKET, SO_REUSEADDR, (const char *)&opt, sizeof(opt));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(8080);

    if (bind(server, (sockaddr *)&addr, sizeof(addr)) == SOCKET_ERROR)
    {
        cerr << "[ERROR] bind failed: " << WSAGetLastError() << "\n";
        cerr << "Try running as Administrator!\n";
        WSACleanup();
        return 1;
    }

    listen(server, 10);
    cout << "\nNetwork Monitor Backend Running\n";
    cout << "Open: http://localhost:8080\n";
    cout << "Run as Administrator for packet capture!\n";
    cout << "Press Ctrl+C to stop\n";

    while (true)
    {
        sockaddr_in client_addr{};
        int client_len = sizeof(client_addr);
        SOCKET client = accept(server, (sockaddr *)&client_addr, &client_len);
        if (client == INVALID_SOCKET)
        {
            if (g_capturing)
            {
                // Socket error during capture, stop gracefully
                g_capturing = false;
            }
            continue;
        }
        try
        {
            thread(handle_client, client).detach();
        }
        catch (const exception &e)
        {
            cerr << "[ERROR] Failed to create client thread: " << e.what() << "\n";
            closesocket(client);
        }
    }

    g_capturing = false;
    closesocket(server);
    WSACleanup();
    return 0;
}
