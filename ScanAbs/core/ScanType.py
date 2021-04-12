from enum import IntFlag
from ipaddress import _BaseAddress


class TCPFlags(IntFlag):
	null = 0
	u = U = urg = URG = urgent = 1
	a = A = ack = ACK = acknowledgment = 2
	p = P = psh = PSH = push = 4
	r = R = rst = RST = reset = 8
	s = S = syn = SYN = synchronize = 16
	f = F = fin = FIN = finish = 32

	xmas = FIN | PSH | URG
	maimon = Maimon = FIN | ACK
	synack = SYN | ACK


class ScanTypeParams:
	"""Type of scan. Subclass for each type"""

	__slots__ = ()


class TCPScanParams(ScanTypeParams):
	__slots__ = ("flags", "zomby", "windowAnalysis", "corruptChecksums")

	@property
	def idle(self):
		return self.zomby

	@idle.setter
	def idle(self, v):
		self.zomby = v

	def __init__(self, flags: TCPFlags = TCPFlags.syn, zomby: _BaseAddress = None, windowAnalysis: bool = False, corruptChecksums: bool = False):
		self.flags = flags
		self.windowAnalysis = windowAnalysis
		self.zomby = zomby
		self.corruptChecksums = corruptChecksums


class ICMPScanParams(ScanTypeParams):
	__slots__ = ("timeAnalysis",)

	def __init__(self, timeAnalysis: bool = False):
		self.timeAnalysis = timeAnalysis


class SCTPScanParams:
	__slots__ = ("cookieEcho", "useAdler32")

	def __init__(self, cookieEcho: bool = False, useAdler32: bool = False):
		self.cookieEcho = cookieEcho
		self.useAdler32 = useAdler32


class UDPScanParams:
	__slots__ = ()


class IPScanParams:
	__slots__ = ()
