import typing
from abc import ABC, abstractmethod
from pathlib import Path

from ..core.ScanParams import CaptureParams, DistributionParams, NetworkParams, ResourceConstraints, ScanParams
from ..core.ScanTask import ScanTask
from ..core.ScanType import ScanTypeParams


class ConfigGenerator(ABC):
	"""Generates text configs for tools"""

	__slots__ = ()

	@abstractmethod
	def genDistributionCfg(self, distribution: DistributionParams, *args, **kwargs):
		raise NotImplementedError

	@abstractmethod
	def genResourceCfg(self, resource: ResourceConstraints, *args, **kwargs):
		raise NotImplementedError

	@abstractmethod
	def genNetworkCfg(self, network: NetworkParams, *args, **kwargs):
		raise NotImplementedError

	@abstractmethod
	def genCaptureCfg(self, capture: CaptureParams, *args, **kwargs):
		raise NotImplementedError

	@abstractmethod
	def genScanTypeCfg(self, scanTypes: typing.Iterable[ScanTypeParams], *args, **kwargs):
		raise NotImplementedError

	@abstractmethod
	def genInteractionCfg(self, format: str, outputFileName: typing.Union[Path, str], *args, **kwargs):
		raise NotImplementedError

	@abstractmethod
	def genTaskCfg(self, ports, excludes, ips):
		raise NotImplementedError

	def __call__(self, scanTask: ScanTask, scanParams: ScanParams, format: str, outputFileName: typing.Union[Path, str], *args, **kwargs):
		cfg = ""

		cfg += self.genDistributionCfg(scanParams.distribution, *args, **kwargs)
		cfg += self.genResourceCfg(scanParams.resource, *args, **kwargs)
		cfg += self.genNetworkCfg(scanParams.network, *args, **kwargs)
		cfg += self.genScanTypeCfg(scanParams.scanTypes, *args, **kwargs)

		if scanParams.capture:
			cfg += self.genCaptureCfg(scanParams.capture, *args, **kwargs)

		cfg += self.genInteractionCfg(format, outputFileName, *args, **kwargs)
		cfg += self.genTaskCfg(scanTask, *args, **kwargs)

		return cfg
