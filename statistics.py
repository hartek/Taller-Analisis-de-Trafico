##############################################################
# statistics.py
# Written by Guillermo Roman (hartek)
# for HoneyCon 2017, thanks for following the white rabbit!
# Gets general statistics about a network traffic capture
##############################################################

# Import necessary libs
import dpkt, sys

# Check the arguments!
if len(sys.argv) != 2: 
	print("Usage: python statistics.py <capture>")
	exit()

# Dictionary with the statistics we will show
stats = {
	"packet_counter": 0, 
	"total_size": 0, 
	"total_ipv4": 0, 
	"total_not_ipv4": 0,
	"total_tcp": 0, 
	"total_udp": 0, 
	"total_not_tcpudp": 0, 
	"total_http": 0,
	"total_https": 0,
	"total_xmpp": 0,
	"total_other_app": 0,
}

# Open the file with read and binary modes
with open(sys.argv[1],"rb") as f: 
	# Create PCAP reader object
	pcap = dpkt.pcap.Reader(f)

	# Loop every packet in PCAP
	for ts,buf in pcap: 
		# Let's count packets and total size!
		stats['packet_counter'] += 1
		stats['total_size'] += len(buf)	

		# Let's assume all the packets are encapsulated in Ethernet frames
		frame = dpkt.ethernet.Ethernet(buf)

		# Inside the Ethernet frame, there is potentially a network packet
		packet = frame.data
		# Let's check if the packet's type is IPv4
		if type(packet) == dpkt.ip.IP: 
			# We will also measure the total size of IPv4 traffic
			stats['total_ipv4'] += len(buf)

			# Similarly, there might be a TCP/UDP segment inside the packet
			segment = packet.data
			# Let's check if the packet's type is TCP!
			if type(segment) == dpkt.tcp.TCP: 
				# Measure the total size of TCP traffic
				stats['total_tcp'] += len(buf)

				# Lastly, which TCP port is used? It gives us hits of the application protocol!
				# Maybe HTTP, HTTPS, XMPP?
				if segment.sport == 80 or segment.dport == 80: 
					stats['total_http'] += len(buf)
				elif segment.sport == 443 or segment.dport == 443: 
					stats['total_https'] += len(buf)
				elif segment.sport == 5222 or segment.dport == 5222: 
					stats['total_xmpp'] += len(buf)
				else: 
					# Measure the others protocols anyways!
					stats['total_other_app'] += len(buf)

			# If not TCP, maybe this is UDP
			elif type(segment) == dpkt.udp.UDP: 
				# Measure the total size of UDP traffic
				stats['total_udp'] += len(buf)
			# This is different, but measure this anyway!
			else: 
				stats['total_not_tcpudp'] += len(buf)

		# Not IPv4? We will ignore this for now, but measure the non-IPv4 size anyways
		else: 
			stats['total_not_ipv4'] += len(buf)


# Finally, let us show off our work!
print("Packet count: %s packets" % (stats['packet_counter']))
print("Total size: %s bytes" % (stats['total_size']))
print("Network sizes: %s bytes IPv4, %s bytes others" % (stats['total_ipv4'], stats['total_not_ipv4']))
print("Transport sizes: %s bytes TCP, %s bytes UDP, %s bytes others" % 
	(stats['total_tcp'], stats['total_udp'], stats['total_not_tcpudp']))
print("Application sizes: %s bytes HTTP, %s bytes HTTPS, %s bytes XMPP, %s bytes others" % 
	(stats['total_http'],stats['total_https'],stats['total_xmpp'],stats['total_other_app']))