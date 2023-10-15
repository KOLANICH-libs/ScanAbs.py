import typing
from abc import abstractmethod
from collections.abc import Mapping
from enum import IntFlag
from ipaddress import _BaseAddress
from pathlib import Path

AnalysisTask = list


class ReportMode(IntFlag):
	open = 1
	closed = 2


class IPortsScanTask(Mapping):
	__slots__ = ("reportMode",)

	def __init__(self, reportMode: ReportMode = ReportMode.open):
		self.reportMode = reportMode

	def __iter__(self) -> typing.Iterator[int]:
		return iter(self.keys())

	@abstractmethod
	def __getitem__(self, port: int) -> AnalysisTask:
		raise NotImplementedError

	@abstractmethod
	def __len__(self) -> int:
		raise NotImplementedError

	@abstractmethod
	def keys(self) -> typing.Iterator[int]:
		raise NotImplementedError

	@abstractmethod
	def values(self) -> typing.Iterator[AnalysisTask]:
		raise NotImplementedError

	@abstractmethod
	def items(self) -> typing.Iterator[typing.Tuple[int, AnalysisTask]]:
		raise NotImplementedError


class PortsScanMatrix(IPortsScanTask):
	__slots__ = ("ports", "analysis")

	def __init__(
		self,
		ports: typing.Iterable[int],
		analysis: AnalysisTask = None,
		reportMode: ReportMode = ReportMode.open,
	):
		super().__init__(reportMode)
		if isinstance(ports, int):
			ports = (ports,)
		self.ports = ports
		self.analysis = analysis

	def __getitem__(self, port: int) -> AnalysisTask:
		return self.analysis

	def __len__(self) -> int:
		return len(self.ports)

	def keys(self) -> typing.Iterator[int]:
		return self.ports

	def values(self) -> typing.Iterator[AnalysisTask]:
		for i in range(len(self.ports)):
			yield self.analysis

	def items(self) -> typing.Iterator[typing.Tuple[int, AnalysisTask]]:
		for p in self.ports:
			yield p, self.analysis


class ScanTask(Mapping):
	__slots__ = ("excludes",)

	def __init__(self, excludes: typing.Union[Path, typing.Iterable[_BaseAddress]]):
		self.excludes = excludes

	def __iter__(self) -> typing.Iterator[_BaseAddress]:
		return iter(self.keys())

	def keys(self) -> typing.Iterator[_BaseAddress]:
		raise NotImplementedError

	def values(self) -> typing.Iterator[IPortsScanTask]:
		raise NotImplementedError

	def items(self) -> typing.Iterator[typing.Tuple[_BaseAddress, IPortsScanTask]]:
		raise NotImplementedError


class ScanMatrix(ScanTask):
	__slots__ = ("ips", "ports")

	"""
	ports,
	singleIpV4sFile: Path = None
	ipv4SubnetsFile: Path = None
	singleIpsV6File: Path = None
	"""

	def __init__(self, ips: typing.Iterable[_BaseAddress], ports: IPortsScanTask, excludes: typing.Union[Path, typing.Iterable[_BaseAddress]] = None):
		super().__init__(excludes)
		if isinstance(ips, _BaseAddress):
			ips = [ips]

		self.ips = ips
		self.ports = ports

	def __getitem__(self, ip: _BaseAddress) -> IPortsScanTask:
		return self.ports

	def __len__(self) -> int:
		return len(self.ips)

	def keys(self) -> typing.Iterator[_BaseAddress]:
		return self.ips

	def values(self) -> typing.Iterator[IPortsScanTask]:
		for i in range(len(self.ips)):
			yield self.ports

	def items(self) -> typing.Iterator[typing.Tuple[_BaseAddress, IPortsScanTask]]:
		for i in self.ips:
			yield i, self.ports
