############################################################
# resolved_dns.py
# Written by Guillermo Roman (hartek)
# for HoneyCon 2017, thanks for following the white rabbit!
# Gets a list of the type A and CNAME resolutions. 
# It outputs a full list of the consulted domains and the 
# resolutions for them.
############################################################

# Import necessary libs
import dpkt, sys, socket

# Check the arguments!
if len(sys.argv) != 2: 
	print("Usage: python resolved_dns.py <capture>")
	exit()

# Create dictionary that will store two dictionaries, one for A registers 
# and another for CNAME registers
resolved_domains = {
	"A": {}, 
	"CNAME": {}
}

# Open the file with read and binary modes
with open(sys.argv[1],"rb") as f: 
	# Create PCAP reader object
	pcap = dpkt.pcap.Reader(f)

	# Loop every packet in PCAP
	for ts,buf in pcap: 
		# For resolutions in DNS responses, we will consider Ethernet frames,
		# IPv4 packets and UDP segments; all others are discarded

		# Is this Ethernet?
		try: 
			frame = dpkt.ethernet.Ethernet(buf)
		except: 
			continue
		
		# Is this IP?
		packet = frame.data
		if type(packet) != dpkt.ip.IP: continue
		
		# Is this TCP?
		segment = packet.data
		if type(segment) != dpkt.udp.UDP: continue

		# The segment should be using port UDP/53 (may use others!)
		if segment.dport != 53 and segment.sport != 53: 
			continue

		# Get DNS responses only!
		try: 
			dns_response = dpkt.dns.DNS(segment.data)
		except: 
			continue

		# These fields describe an usual DNS response
		if dns_response.qr != dpkt.dns.DNS_R: continue
		if dns_response.opcode != dpkt.dns.DNS_QUERY: continue
		if dns_response.rcode != dpkt.dns.DNS_RCODE_NOERR: continue
		if len(dns_response.an) < 1: continue

		# Iterate through the possible multiple answers in the response
		for answer in dns_response.an: 
			# Check if the answer is for a CNAME type
			if answer.type == dpkt.dns.DNS_CNAME: 
				# Then, check if the CNAME record has been stored already
				if answer.cname in resolved_domains['CNAME']: 
					# Now, check if the resolution has been stored already in the CNAME key
					if answer.name not in resolved_domains['CNAME'][answer.cname]: 
						# If this is new, append to the list! If not... do not
						resolved_domains['CNAME'][answer.cname].append(answer.name)
				# If the CNAME record is new, add a new key
				else: 
					resolved_domains['CNAME'][answer.name] = [answer.cname,]
			# Check if the answer is for an A type
			elif answer.type == dpkt.dns.DNS_A:
				# Then, check if the A record has been stored already
				if answer.name in resolved_domains['A']: 
					# Now, check if the resolution has been stored already in the A key
					if socket.inet_ntoa(answer.rdata) not in resolved_domains['A'][answer.name]:
						# If this is new, append to the list! If not... do not
						resolved_domains['A'][answer.name].append(socket.inet_ntoa(answer.rdata))
				# If the A record is new, add a new key
				else: 
					resolved_domains['A'][answer.name] = [socket.inet_ntoa(answer.rdata),]


	# Print the results!
	for name,cnames in resolved_domains['CNAME'].items(): 
		print("%s: " % (name))
		for cname in cnames: 
			print("\t%s" % (cname))
	for name,addrs in resolved_domains['A'].items(): 
		print("%s: " % (name))
		for addr in addrs: 
			print("\t%s" % (addr))