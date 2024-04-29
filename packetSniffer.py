import socket
from struct import unpack
def packetSniffer():
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
    print("Packet Sniffing...")
    try:
        while True:
            raw_data, addr = s.recvfrom(65536)
            dest_mac, src_mac, eth_proto, data = unpack('! 6s 6s H', raw_data[:14])
            print(f"Destination MAC: {dest_mac.hex()}")
            print(f"Source MAC: {src_mac.hex()}")
            print(f"Ethernet Protocol: {eth_proto}")
            print(f"Data: {data.hex()}")
    except KeyboardInterrupt:
        print("Exiting...")
if __name__ == "__main__":
    packetSniffer()