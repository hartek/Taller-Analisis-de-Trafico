############################################################
# user_agents.py
# Written by Guillermo Roman (hartek)
# for HoneyCon 2017, thanks for following the white rabbit!
# Gets a list of the user agents detected in the capture, 
# ordered by number of requests sent
############################################################

# Import necessary libs
import dpkt, sys, operator

# Check the arguments!
if len(sys.argv) != 2: 
	print("Usage: python user_agents.py <capture>")
	exit()

# Create dictionary that will store the user agent list
ua_dict = {}

# Open the file with read and binary modes
with open(sys.argv[1],"rb") as f: 
	# Create PCAP reader object
	pcap = dpkt.pcap.Reader(f)

	# Loop every packet in PCAP
	for ts,buf in pcap: 
		# For user agents in HTTP requests, we will consider Ethernet frames,
		# IPv4 packets and TCP segments; all others are discarded

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
		if type(segment) != dpkt.tcp.TCP: continue

		# The segment should be using port TCP/80 (may use others!)
		if segment.dport != 80 and segment.sport != 80: 
			continue

		# Get HTTP requests only
		try: 
			http_request = dpkt.http.Request(segment.data)
		except: 
			continue

		# Get user agent (if exists) and add to dictionary!
		if 'user-agent' in http_request.headers: 
			ua = http_request.headers['user-agent']
			if ua in ua_dict: 
				ua_dict[ua] += 1
			else: 
				ua_dict[ua] = 1

	# Transform the dictionary into an ordered list of tuples (what?)
	sorted_dict = sorted(ua_dict.items(), key=operator.itemgetter(1),reverse=True)
	# Print the results!
	for ua,times in sorted_dict: 
		print("%s: %s times" % (ua,times))
