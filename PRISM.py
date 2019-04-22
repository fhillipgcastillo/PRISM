from scapy.all import sniff, Raw, IP, UDP, wrpcap, hexdump 
from shared import descriptBase64Content


def getSniffPackages(filter=False, count=10):
	try:
		pkts = sniff(filter=filter, count=count)
		return pkts
	except Exception as e:
		raise
	return []

def monitorNetwork(filter=False, min_amount=10, DEBUG=False, save_pcks=False):
	_min=0
	_max = min_amount
	print "Starting to sniff every %i packages..."%min_amount
	packages = []
	while True:
		pkts = getSniffPackages(filter, min_amount)
		if save_pcks: wrpcap("data\\pkgs-%i-%i.cap"%(_min, _max), pkts)
		_min = _max
		_max += min_amount
		packages += pkts
		# print min_amount, "package read.\n"
		# pkts.nsummary()
		# print "=============================="
		# # hops, sport = trace_route(pkts)
		# # coordinates = map_ip(hops)
		# for pkt in pkts:
		# 	if pkt.haslayer(Raw):
		# 		print descriptBase64Content(pkt.getlayer(Raw).load)
		# 	# else:
		# 	# 	pkt.show()
		# 		print "=============================="
		# 	# filter_packat_by_string(pkt, 'attachment')
		# 	# filter_packat_by_string(pkt, 'amarok')
		# 	# filter_packat_by_string(pkt, 'youporn')
		# break
		# packages.summary(prn=lambda x:x.sprintf("{IP:%IP.src% -> %IP.dst%\n}"
		# 									"{Raw:%Raw.load%\n}"))

		# print "C to continue"
		# print "S to Summarize"
		# print "R to Show raw"
		# option = raw_input("... ")


