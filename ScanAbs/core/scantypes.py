from .ScanType import ICMPScanParams, IPScanParams, SCTPScanParams, TCPFlags, TCPScanParams, UDPScanParams


tcpSyn = TCPScanParams(TCPFlags.syn)
tcpSynOpt = TCPScanParams(TCPFlags.syn)
tcpAck = TCPScanParams(TCPFlags.ack)
tcpSynAck = TCPScanParams(TCPFlags.synack)
tcpFin = TCPScanParams(TCPFlags.fin)
tcpMaimon = TCPScanParams(TCPFlags.maimon)

icmpEcho = ICMPScanParams(False)
icmpEchoTime = ICMPScanParams(True)
udp = UDPScanParams()
ip = IPScanParams()
sctp = SCTPScanParams(False)
sctpCookieEcho = SCTPScanParams(True)

stsSpec = {
	"tcp": {
		"syn": tcpSyn,
		"synOpt": tcpSynOpt,
		"ack": tcpAck,
		"synAck": tcpSynAck,
		"fin": tcpFin,
		"maimon": tcpMaimon
	},
	"icmp": {
		"echo": icmpEcho,
		"time": icmpEchoTime
	},
	"udp": udp,
	"ip": ip,
	"sctp": {
		"simple": sctp,
		"cookieEcho": sctpCookieEcho
	}
}
	
def parseScanTypeFromString(scanTypeString):
	sts = scanTypeString.split(":")
	res = stsSpec
	for comp in sts:
		res = res[comp]
	return res
