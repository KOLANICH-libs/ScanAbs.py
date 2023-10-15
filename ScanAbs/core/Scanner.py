import typing
from abc import ABC, abstractmethod

from .ScanJob import ScanJob
from .ScannerMeta import ScannerMeta
from .ScanParams import ScanParams
from .ScanTask import ReportMode, ScanTask


class Scanner:
	__slot__ = ("params",)

	META = None  # type: ScannerMeta

	def __init__(self, params: ScanParams):
		self.params = params

	@abstractmethod
	def __call__(self, task: ScanTask) -> ScanJob:
		raise NotImplementedError
