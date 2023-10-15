import typing
from ipaddress import _BaseAddress
from pathlib import Path
from enum import IntEnum

from netaddr import EUI

from .ScannerMeta import OSILayer
from .ScanTask import ReportMode
from .ScanType import ScanTypeParams
from .scantypes import tcpSyn


class ResourceConstraints:
	__slots__ = ("reportMode", "rate", "bandwidth", "retries", "dryRun", "timeout", "waitTime", "ignoreRateLimits")

	def __init__(self, reportMode: ReportMode = ReportMode.open, rate: int = None, bandwidth: int = None, retries: int = None, dryRun: bool = False, waitTime: int = None, timeout: int = None, ignoreRateLimits: bool = False):
		self.reportMode = reportMode
		self.rate = rate
		self.bandwidth = bandwidth
		self.retries = retries
		self.dryRun = dryRun
		self.waitTime = waitTime
		self.timeout = timeout
		self.ignoreRateLimits = ignoreRateLimits


PortRangeT = typing.Union[int, range]


class L2Device:
	__slots__ = ("mac",)

	def __init__(self, mac: EUI = None):
		self.mac = mac


class L3Device:
	__slots__ = ("ip", "listenPort")

	def __init__(self, ip: _BaseAddress = None, port: PortRangeT = None):
		self.ip = ip
		self.port = port


class L2L3Device:
	__slots__ = (
		"l3",
		"l2",
	)

	def __init__(self, l3: L3Device = None, l2: L2Device = None):
		self.l3 = l3
		self.l2 = l2


class GatewayParams(L2Device):
	__slots__ = ()


class NICParams(L2L3Device):
	__slots__ = ()


DeviceParamsTComponent = typing.Union[L3Device, L2Device, L2L3Device]


class DeviceParamsPair:
	__slots__ = ("v4", "v6")

	def __init__(self, v4: DeviceParamsTComponent = None, v6: DeviceParamsTComponent = None):
		self.v4 = v4
		self.v6 = v6


DeviceParamsT = typing.Union[DeviceParamsPair, DeviceParamsTComponent]
L2DeviceParamsT = typing.Union[DeviceParamsPair, L2L3Device]
L3DeviceParamsT = typing.Union[DeviceParamsPair, L2L3Device]
L2L3DeviceParamsT = typing.Union[DeviceParamsPair, L2L3Device]


class ProxyType(IntEnum):
	socks5 = 1


class Proxy(L3Device):
	__slots__ = ("type",)

	def __init__(self, ip: _BaseAddress, typ: ProxyType, port: PortRangeT = None):
		self.type = typ
		super().__init__(ip, port)


class NetworkParams:
	__slots__ = ("osiLayer", "ttl", "adapterName", "sender", "gateway", "proxies")

	def __init__(self, osiLayer: OSILayer = None, ttl: int = None, adapterName: str = None, sender: L2L3DeviceParamsT = None, gateway: L2DeviceParamsT = None, proxies: typing.Iterable[Proxy] = ()):
		self.osiLayer = osiLayer
		self.ttl = ttl
		self.adapterName = adapterName

		if sender is None:
			sender = DeviceParamsPair(NICParams(), NICParams())

		self.sender = sender

		if gateway is None:
			gateway = DeviceParamsPair(GatewayParams(), GatewayParams())

		self.gateway = gateway
		self.proxies = proxies


class DistributionParams:
	__slots__ = ("countOfShards", "currentShard", "seed")

	def __init__(self, countOfShards: int = 1, currentShard: int = 1, seed: int = None):
		self.countOfShards = countOfShards
		self.currentShard = currentShard
		self.seed = seed


class CaptureParams:
	__slots__ = ("banners", "pcapResponsesFile")

	def __init__(self, banners: bool = False, pcapResponsesFile: Path = None):
		self.banners = banners
		self.pcapResponsesFile = pcapResponsesFile


class ScanParams:
	__slots__ = ("scanTypes", "network", "capture", "distribution", "resource")

	def __init__(self, scanTypes: typing.Iterable[ScanTypeParams] = (tcpSyn,), resource: ResourceConstraints = None, network: NetworkParams = None, distribution: DistributionParams = None, capture: CaptureParams = None):
		self.scanTypes = scanTypes

		if network is None:
			network = NetworkParams()

		self.network = network

		if capture is None:
			capture = CaptureParams(capture)

		self.capture = capture

		if distribution is None:
			distribution = DistributionParams()

		self.distribution = distribution

		if resource is None:
			resource = ResourceConstraints()

		self.resource = resource
