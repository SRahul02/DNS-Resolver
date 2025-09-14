from scapy.utils import PcapReader
from scapy.layers.dns import DNS
from datetime import datetime
import socket
import struct

cnt = 0 # Maintains a cnt of how many pkts have been processed
dns_pkts = [] #To store the list of DNS query pkts

with PcapReader("8.pcap") as pcap:
    for pkt in pcap:
        if pkt.haslayer(DNS) and pkt[DNS].qr == 0: # Checking if the pkt is a DNS query.
            seq_id = f"{cnt:02}" # Get the seq_id or seq_no (0-based, 2 digits) of the pkt
            timestamp = datetime.now().strftime("%H%M%S") # Creates real time timestamp to add to hdr
            cstm_hdr = (timestamp+seq_id).encode("utf-8") # Creating the hdr
           
            dns_pkts.append({ #Adding the pkt to the list of valid pkts with their custom hdrs
                "custom_header": cstm_hdr,
                "original_packet": pkt[DNS]
            })

        cnt += 1
        if cnt % 50000 == 0:   # progress update
            print(f"Processed {cnt} packets...")

print()

i=1
for x in dns_pkts: # Printing the DNS pkts for validation
    print("----New pkt",i,"---->")
    i+=1
    for key, value in x.items():
        print(f"{key}: {value}")
    print()
       
print("========Done========")
print("Total Number of pkts scanned =",cnt)
print("Total number of DNS query packets =",i-1)        

server_ip = '127.0.0.1'
server_port = 12345

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect((server_ip,server_port))

for pkt in dns_pkts:  # Sending 1 pkt at a time to the server
    packet_to_send = pkt['custom_header'] + bytes(pkt['original_packet'])
    siz = len(packet_to_send)
    client.sendall(struct.pack("!I",siz)+packet_to_send)

client.close()