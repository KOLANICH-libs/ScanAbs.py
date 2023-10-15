import typing
from collections.abc import Mapping
from io import StringIO
from ipaddress import _BaseAddress


class OpenPort:
	__slots__ = ("time", "delay", "reason")

	def __init__(self, time, delay: int = None, reason=None):
		self.time = time
		self.delay = delay
		self.reason = reason

	def __str__(self):
		return "✅ (" + str(self.reason) + ", " + str(self.delay) + ", " + str(self.time) + ")"


class PortProbeResult(OpenPort):
	__slots__ = ("service",)

	def __init__(self, time, service, delay: int = None, reason=None):
		super().__init__(time, delay, reason)
		self.service = service

	def __str__(self):
		return super().__str__() + " " + str(self.service)


PortNoToResMappingT = typing.Mapping[int, OpenPort]
PortNoToResMappingCtor = dict


class L3ProtoCollection(Mapping):
	__slots__ = ("ports",)

	def __init__(self):
		self.ports = PortNoToResMappingCtor()

	def __iter__(self) -> typing.Iterator[_BaseAddress]:
		return iter(self.keys())

	def __getitem__(self, port: int) -> OpenPort:
		return self.ports[port]

	def __setitem__(self, port: int, v: OpenPort):
		self.ports[port] = v

	def __len__(self) -> int:
		return len(self.ports)

	def keys(self) -> typing.Iterator[int]:
		return self.ports.keys()

	def values(self) -> typing.Iterator[OpenPort]:
		return self.ports.values()

	def items(self) -> typing.Iterator[typing.Tuple[int, OpenPort]]:
		return self.ports.items()

	def get(self, port: int) -> OpenPort:
		res = self.ports.get(port, default)
		if res is None:
			self.ports[port] = res = OpenPort(port)
		return res


class ReportRecord:
	PROTOS = ("tcp", "udp")
	__slots__ = ("addr",) + PROTOS

	def __init__(self, addr):
		self.addr = addr  # type: _BaseAddress
		for pr in self.__class__.PROTOS:
			setattr(self, pr, L3ProtoCollection())  # type: PortNoToResMappingT

	def __str__(self):
		with StringIO() as r:
			for pr in self.__class__.PROTOS:
				prBin = getattr(self, pr)
				for port, status in prBin.items():
					print("\t", port, status, file=r)
			return r.getvalue()


IP2RecordMappingT = typing.Mapping[_BaseAddress, ReportRecord]
IP2RecordMappingCtor = dict


class Report:
	__slots__ = ("report",)

	def __init__(self):
		self.report = IP2RecordMappingCtor()  # type: IP2RecordMappingT

	def append(self, rec: ReportRecord):
		self.report[rec.addr] = rec

	def __iter__(self) -> typing.Iterator[_BaseAddress]:
		return iter(self.keys())

	def __getitem__(self, addr: _BaseAddress) -> ReportRecord:
		return self.report[addr]

	def __setitem__(self, addr: _BaseAddress, v: ReportRecord):
		self.report[addr] = v

	def __len__(self) -> int:
		return len(self.report)

	def keys(self) -> typing.Iterator[_BaseAddress]:
		return self.report.keys()

	def values(self) -> typing.Iterator[ReportRecord]:
		return self.report.values()

	def items(self) -> typing.Iterator[typing.Tuple[_BaseAddress, ReportRecord]]:
		return self.report.items()

	def get(self, addr: _BaseAddress) -> ReportRecord:
		res = self.report.get(addr, None)
		if res is None:
			self.report[addr] = res = ReportRecord(addr)
		return res

	def __str__(self):
		with StringIO() as r:
			for addr, rec in self.items():
				print(addr, "\n", rec, file=r)
			return r.getvalue()
