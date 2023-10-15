import sys
import typing
from datetime import datetime
from ipaddress import IPv4Address, IPv4Network, IPv6Address, IPv6Network, _BaseAddress, ip_address
from pathlib import Path

import sh
from MempipedPath import MempipedPathRead
from netaddr import EUI, mac_eui48

from ...core.Report import OpenPort, Report, ReportRecord
from ...core.ScanJob import ScanJob, SynchronousJob
from ...core.Scanner import Scanner
from ...core.ScannerMeta import OSILayer, ResponseCaptureMethod, ScannerMeta
from ...core.ScanParams import CaptureParams, DeviceParamsPair, DistributionParams, NetworkParams, ResourceConstraints, ScanParams
from ...core.ScanTask import ReportMode, ScanMatrix, ScanTask
from ...core.ScanType import ScanTypeParams
from ...utils.ConfigGenerator import ConfigGenerator

from ...core.scantypes import tcpSyn

try:
	from .kaitai.masscan import Masscan

	def kaitaiResultParser(res):
		res = Masscan.from_bytes(bytes(res))
		report = Report()
		for r in res.records:
			ip = ip_address(r.payload.ip_addr)
			rec = report.get(ip, None)
			if rec is None:
				report[ip] = rec = ReportRecord(ip)
				report.append(rec)

			time = datetime.fromtimestamp(r.payload.timestamp)
			port = r.payload.port
			ipProtoName = r.payload.ip_proto.__name__

			"""
			r.payload
			r.payload.app_proto
			r.payload.is_open
			"""
			if ipProtoName == "tcp":
				coll = rec.tcp
			elif ipProtoName == "udp":
				coll = rec.udp
			else:
				raise KeyError(r.payload.ip_proto, "Unsupported protocol")

			coll[port] = OpenPort(time, r.records[0].payload.ttl, r.records[0].payload.reason)

		return report

	isJsonFormat = False
	resultParser = kaitaiResultParser

except BaseException:
	from ...utils.json import json

	def jsonResultParser(res):
		res = json.loads(str(res, encoding="utf-8"))
		report = Report()
		for r in res:
			rec = ReportRecord(ip_address(r["ip"]))

			time = datetime.fromtimestamp(int(r["timestamp"]))

			for p in r["ports"]:
				if p["proto"] == "tcp":
					coll = rec.tcp
				elif p["proto"] == "udp":
					coll = rec.udp
				else:
					raise KeyError(p["proto"], "Unsupported protocol")
				# p["status"]

				coll[p["port"]] = OpenPort(time, p["ttl"], p["reason"])
			report.append(rec)
		return report

	isJsonFormat = True
	resultParser = jsonResultParser


class MasscanConfigGenerator(ConfigGenerator):
	"""
	ToDO:
	--ping
	--exclude
	--pfring
	"""

	__slots__ = ()

	def genResourceCfg(self, resource: ResourceConstraints, *args, **kwargs):
		cfg = ""

		if resource.dryRun:
			cfg = "offline = true\n"

		if resource.rate:
			cfg += "rate = " + str(rate) + "\n"

		waitTime = resource.waitTime
		if waitTime:
			if waitTime == float("inf"):
				waitTime = "forever"
			cfg += "wait = " + str(waitTime) + "\n"

		if resource.retries:
			cfg += "retries = " + str(retries) + "\n"

		if resource.bandwidth:
			cfg += "bandwidth = " + str(bandwidth) + "\n"

		if resource.reportMode & ReportMode.closed:
			cfg += "open-only = true\n"

		return cfg

	def genDistributionCfg(self, distribution: DistributionParams, *args, **kwargs):
		cfg = ""

		if distribution.seed is not None:
			cfg += "seed = " + str(distribution.seed) + "\n"

		cfg += "shard = " + "/".join((str(distribution.currentShard), str(distribution.countOfShards))) + "\n"

		return cfg

	def genNetworkCfg(self, network: NetworkParams, *args, **kwargs):
		cfg = ""

		if network.ttl:
			cfg += "ttl = " + str(network.ttl) + "\n"

		if network.adapterName:
			cfg += "adapter =  " + str(network.adapterName) + "\n"

		if network.sender.mac:
			cfg += "adapter-mac = " + network.sender.mac.format(mac_eui48) + "\n"

		if network.sender.ip:
			cfg += "adapter-ip = " + str(network.sender.ip) + "\n"

		if network.sender.portRange:
			if isinstance(sendPortRange, range):
				rlen = sendPortRange.stop - sendPortRange.start
				if rlen & (rlen - 1):
					raise ValueError("masscan requires port range be power of 2")
				sendPort = str(sendPortRange.start) + "-" + str(sendPortRange.stop)
			else:
				sendPort = str(sendPort)

			cfg += "adapter-port = " + sendPort + "\n"

		if network.gateway.mac:
			if isinstance(network.gateway.mac, EUI):
				gatewayMac = (gatewayMac, gatewayMac)

			cfg += "router-mac-ipv4 = " + gatewayMac[0].format(mac_eui48) + "\n"
			if len(gatewayMac) > 1:
				cfg += "router-mac-ipv6 = " + gatewayMac[1].format(mac_eui48) + "\n"

		return cfg

	def genCaptureCfg(self, capture: CaptureParams, *args, **kwargs):
		cfg = ""
		if capture.banners:
			cfg += "banners = true\n"

		if capture.pcapResponsesFile:
			cfg += "pcap-filename = " + str(capture.pcapResponsesFile) + "\n"

		cfg += """nocapture = servername\n"""

		return cfg

	def genScanTypeCfg(self, scanTypes: typing.Iterable[ScanTypeParams], *args, **kwargs):
		cfg = ""

		for scanType in scanTypes:
			if isinstace(scanType, ICMPScanParams):
				cfg += "ping = true\n"

		return cfg

	def genInteractionCfg(self, format, outputFileName, *args, **kwargs):
		return "\n".join(("output-filename = " + str(outputFileName), "output-format = " + format)) + "\n"

	def genTaskCfg(self, task: ScanTask, *args, **kwargs):
		cfg = ""
		for p in task.ports:
			cfg += "ports = " + str(p) + "\n"

		cfg += "# TARGET SELECTION (IP, PORTS, EXCLUDES)\n"

		if task.excludes is not None:
			if isinstance(task.excludes, Path):
				cfg += "excludefile = " + str(task.excludes) + "\n"
			else:
				for ip in task.excludes:
					cfg += "exclude = " + str(ip) + "\n"

		for ip in task.ips:
			cfg += "range = " + str(ip) + "\n"
		return cfg


class MasscanBackend(Scanner):
	__slots__ = ("masscanCmd",)

	META = ScannerMeta(
		name="masscan",
		types=(tcpSyn,),
		osiLayers=(OSILayer.Ethernet),
		ipKinds=(IPv4Address, IPv4Network, IPv6Address, IPv6Network),
		scanOrientations=(ScanMatrix),
		acceptsInputsAsFile=False,
		responsesCaptureMethods=(ResponseCaptureMethod.pcap, ResponseCaptureMethod.banner),
	)

	def __init__(
		self,
		scanParams: ScanParams,
		masscanCmd: typing.Union[str, Path] = "masscan",
	):
		super().__init__(scanParams)
		self.masscanCmd = sh.Command(masscanCmd)

	def __call__(self, task: ScanTask) -> ScanJob:
		if isinstance(task, ScanMatrix):
			cg = MasscanConfigGenerator()
			cfgText = generateCfg(
				task,
				self.scanParams,
				"-",
				("json" if isJsonFormat else "binary"),
				adapter=self.adapter,
			)
			with MempipedPathRead(cfgText) as cfgFile:
				res = self.masscanCmd(c=cfgFile, _err=sys.stderr)

			return SynchronousJob(resultParser(res.stdout))
		else:
			raise NotImplementedError("Masscan doesn't fit for per-host params")
