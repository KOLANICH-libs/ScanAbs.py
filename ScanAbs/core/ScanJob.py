from abc import ABC, abstractmethod

from .Report import Report


class ScanJob(ABC):
	__slots__ = ()

	@property
	@abstractmethod
	def finished(self) -> bool:
		raise NotImplemented

	@abstractmethod
	def getResults(self) -> Report:
		raise NotImplemented


class SynchronousJob(ScanJob):
	__slots__ = ("results",)

	@property
	def finished(self) -> bool:
		return True

	def getResults(self) -> Report:
		return self.results

	def __init__(self, results):
		self.results = results
