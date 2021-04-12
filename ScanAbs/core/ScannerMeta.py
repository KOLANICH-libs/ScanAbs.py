import typing
from enum import IntEnum, IntFlag
from ipaddress import _BaseAddress, _BaseNetwork

from .ScanTask import ReportMode, ScanTask
from .ScanType import ScanTypeParams


class OSILayer(IntEnum):
	Ethernet = 2
	IP = 3


class ResponseCaptureMethod(IntFlag):
	raw = 1
	pcap = 2
	banner = 4


class ScannerMeta:
	__slots__ = (
		"name",
		"types",
		"osiLayers",
		"ipKinds",
		"scanOrientations",
		"sharded",
		"supportsBlacklistFiles",
		"acceptsInputsAsFile",
		"responsesCaptureMethods",
		"supportedReportModes",
	)

	def __init__(
		self,
		name: str,
		types: typing.Tuple[ScanTypeParams, ...],
		osiLayers: typing.Tuple[OSILayer, ...],
		ipKinds: typing.Tuple[typing.Union[_BaseNetwork, _BaseAddress], ...],
		scanOrientations: typing.Tuple[typing.Type[ScanTask], ...],
		acceptsInputsAsFile: bool,
		responsesCaptureMethods: typing.Tuple[ResponseCaptureMethod, ...],
		supportsBlacklistFiles: bool = True,
		sharded: bool = True,
		supportedReportModes: ReportMode = ReportMode.open | ReportMode.closed,
	):
		self.name = name
		self.types = types
		self.osiLayers = osiLayers
		self.ipKinds = ipKinds
		self.scanOrientations = scanOrientations
		self.sharded = sharded
		self.supportsBlacklistFiles = supportsBlacklistFiles
		self.acceptsInputsAsFile = acceptsInputsAsFile
		self.responsesCaptureMethods = responsesCaptureMethods
		self.supportedReportModes = supportedReportModes
