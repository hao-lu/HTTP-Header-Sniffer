#include <pcap.h>
#include <stdio.h>

#define SIZE_ETHERNET 14
#define ETHERNET_ADDRESS_SIZE 6
struct  ethernet_header {
    u_char  ether_dest_host[ETHERNET_ADDRESS_SIZE];
    u_char  ether_source_host[ETHERNET_ADDRESS_SIZE];
    u_short ether_type;
};

// Prototypes 
void grab_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
void write_post_file(const u_char* temp_ptr, int byte_count, int payload_size, int count);

int main(int argc, char *argv[]) {
    // Session handle for creating a sniffing session 
    pcap_t *handle;
    // Device to sniff on 
    char *dev;
    char errbuf[PCAP_ERRBUF_SIZE];
    // Filtering traffic 
    struct bpf_program fp;
    char filter_exp[] = "tcp port 80";
    // Our netmask
    bpf_u_int32 mask;
    // Our IP
    bpf_u_int32 net;
    // Header of packet given by pcap
    struct pcap_pkthdr header;
    // Packet sniffed
    const u_char *packet;

    // Initialize the device
    dev = pcap_lookupdev(errbuf);
    if (dev == NULL) {
        fprintf(stderr, "No default device found: %s\n", errbuf);
        return(2);
    }
    // Properties of device 
    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
        fprintf(stderr, "No netmask for device found: %s: %s\n", dev, errbuf);
        net = 0;
        mask = 0;
    }
    // dev - handle
    // BUFSIZ - max # of bytes to be captured
    // 1 - promiscuous mode
    // 1000 - read timeout (ms)
    // errbuf - error message
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "No open device %s: %s\n", dev, errbuf);
        return(2);
    }
    // Compile and apply the traffic filter 
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return(2);
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return(2);
    }

    // handle - session handle
    // 10 - number of packets to sniff before returning
    // grab_packet - callback method 
    pcap_loop(handle, 0, grab_packet, NULL);
    pcap_freecode(&fp);
    pcap_close(handle);

    return 0;
}

void grab_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    static int count = 0;
    count++;
    // Ethernet header is always 14 bytes 
    struct ethernet_header *ethernet_header_ptr;
    ethernet_header_ptr = (struct ethernet_header *) packet;

    // IP 20 bytes TCP 20 bytes
    const u_char *ip_header;
    const u_char *tcp_header;
    const u_char *payload;

    // Pointer steps away 
    int ip_header_size;
    int tcp_header_size;
    int payload_size;

    ip_header = packet + SIZE_ETHERNET;

    // Source IP is 13 - 16 byte 
    u_char source_ip = *(ip_header + 12);
    u_char source_ip_1 = *(ip_header + 13);
    u_char source_ip_2 = *(ip_header + 14);
    u_char source_ip_3 = *(ip_header + 15);
    // Destination IP is 17 - 20 byte 
    u_char dest_ip = *(ip_header + 16);
    u_char dest_ip_1 = *(ip_header + 17);
    u_char dest_ip_2 = *(ip_header + 18);
    u_char dest_ip_3 = *(ip_header + 19);

    // The first byte of the IP Header contains the version in the first half and IP Header size(IHL)
    // in the second half 
    ip_header_size = ((*ip_header) & 0x0F);
    ip_header_size = ip_header_size * 4;

    tcp_header = packet + SIZE_ETHERNET + ip_header_size;

    // Source port is the first 2 bytes (Byte 0 & 1)
    u_char source_port = *(tcp_header);
    u_char source_port_1 = *(tcp_header + 1);
    // Destination port is the next 2 bytes (Byte 2 & 3)
    u_char dest_port = *(tcp_header + 2);
    u_char dest_port_1 = *(tcp_header + 3);

    // The header size of TCP is in the first half of the byte 12 
    tcp_header_size = ((*(tcp_header + 12)) & 0xF0) >> 4;
    tcp_header_size = tcp_header_size * 4;
    
    payload_size = header->caplen - (SIZE_ETHERNET + ip_header_size + tcp_header_size);
    payload = packet + (SIZE_ETHERNET + ip_header_size + tcp_header_size);

    char *header_type = (source_port_1 != 0x50) ? "Request" :  "Response";
    printf("%d %u.%u.%u.%u:%u%u %u.%u.%u.%u:%u%u HTTP %s\n", count, source_ip, 
        source_ip_1, source_ip_2, source_ip_3,
        source_port, source_port_1,
        dest_ip, dest_ip_1, dest_ip_2, dest_ip_3,
        dest_port, dest_port_1,
        header_type);
    
    if (payload_size > 0) {
        const u_char *temp_ptr = payload;
        int byte_count = 0;
        int CRLF = 0;
        int request_or_response_type = *temp_ptr;
        // If GET or POST request or response
            if (*temp_ptr == 0x47 || *temp_ptr == 0x48 || *temp_ptr == 0x50) {
            while (byte_count++ < payload_size) {
                if (*temp_ptr == 0x0d) {
                    printf("\\r\\n\n");
                    temp_ptr++;
                    if (CRLF) {
                        // Entity body 
                        // POST, then write to file
                        if (request_or_response_type == 0x50) {
                            write_post_file(temp_ptr, byte_count, payload_size, count);
                        }
                        return;
                    }
                    CRLF = 1;
                    // Get the next element after \n
                    temp_ptr++;
                }
                else {
                    CRLF = 0;
                    printf("%c", *temp_ptr);
                    temp_ptr++;
                }

            }
            printf("\n");
        }
    }
    else 
        return;
}

void write_post_file(const u_char* temp_ptr, int byte_count, int payload_size, int count) {
    // Max 999 
    char file_name[sizeof "000.txt"];
    sprintf(file_name, "%d.txt", count);
    FILE *f = fopen(file_name, "w");
    while (byte_count++ < payload_size) {
        fprintf(f, "%c", *temp_ptr);
        temp_ptr++;
    }
    fclose(f);
}
