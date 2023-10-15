import sys
import typing
from contextlib import suppress as dummyCtx
from datetime import datetime
from ipaddress import IPv4Address, IPv4Network, IPv6Address, IPv6Network, _BaseAddress, ip_address
from pathlib import Path
from struct import Struct

import netifaces
import sh
from MempipedPath import MempipedPathRead
from netaddr import EUI
from netaddr.strategy.eui48 import mac_eui48

from ..core.Report import OpenPort, Report, ReportRecord
from ..core.ScanJob import ScanJob, SynchronousJob
from ..core.Scanner import Scanner
from ..core.ScannerMeta import OSILayer, ScannerMeta
from ..core.ScanParams import CaptureParams, DeviceParamsPair, DistributionParams, NetworkParams, ResourceConstraints, ScanParams
from ..core.ScanTask import ReportMode, ScanMatrix, ScanTask
from ..core.ScanType import ScanTypeParams
from ..utils.ConfigGenerator import ConfigGenerator
from ..utils.json import json
from ..utils.randint import randInt

from ..core import scantypes

netifaces.ifaddresses("teredo")


u32native = Struct("=I")
u64native = Struct("=Q")


def nativeInt2IpAddress(n: int):
	if n & 0xffffffff_00000000:
		return IPv6Address(u64native.pack(n))
	else:
		return IPv4Address(u32native.pack(n))


def resultParser(res):
	report = Report()
	for res in res.splitlines():
		r = json.loads(str(res, encoding="utf-8"))
		print(r)
		rec = report.get(nativeInt2IpAddress(r["daddr_raw"]))

		time = datetime.fromtimestamp(r["timestamp_ts"] + r["timestamp_us"] / 1000000)

		if r["classification"] in {"synack", "rst"}:
			coll = rec.tcp
		elif r["classification"] == "udp":
			coll = rec.udp
		else:
			raise KeyError(r["classification"], "Unsupported protocol")
		# r["success"]

		coll[r["sport"]] = OpenPort(time, r["ttl"])
		report.append(rec)
	return report


"""
saddr_raw          int: network order integer form of source IP address
ipid               int: IP identification number of response
sport              int: TCP source port
seqnum             int: TCP sequence number
acknum             int: TCP acknowledgement number
window             int: TCP window
classification  string: packet classification
"""

nowUsedOutputFields = (
	"success",
	"daddr_raw",
	"timestamp_ts",
	"timestamp_us",
	"dport",
	"ttl",
)
nowUselessOutputFields = (
	"saddr_raw",
	"ipid",
	"sport",
	"seqnum",
	"acknum",
	"window",
	"classification",
)
allOutputFields = nowUsedOutputFields + nowUselessOutputFields


supportedScanTypes = {
	scantypes.tcpSyn: "tcp_synscan",
	scantypes.tcpSynAck: "tcp_synackscan",
	scantypes.udp: "udp",
	scantypes.tcpSynOpt: "tcp_synopt", # https://github.com/tumi8/zmap/blob/master/src/probe_modules/module_ipv6_tcp_synopt.c  What is it?
	scantypes.icmpEcho: "icmp_echoscan",
	scantypes.icmpEchoTime: "icmp_echo_time",
}


def getScanTypeStr(scanType: ScanTypeParams, isIpV6: bool = False) -> str:
	res = supportedScanTypes[scanType]
	if isIpV6:
		if res[:5] == "icmp_":
			res = "icmp6_" + res[5:]
		else:
			res = "ipv6_"
	return res


class ZMapConfigGenerator(ConfigGenerator):
	__slots__ = ()

	def genDistributionCfg(self, distribution: DistributionParams, *args, **kwargs):
		cfg = ""
		seedRequired = False

		if distribution.currentShard != 1 or distribution.countOfShards != 1:
			cfg += "shard = " + str(distribution.currentShard) + "\n"
			cfg += "shards = " + str(distribution.countOfShards) + "\n"
			seedRequired = True

		seed = distribution.seed

		if seed is None:
			if seedRequired:
				seed = randInt("I")

		if seed:
			cfg += "seed = " + str(distribution.seed) + "\n"

		return cfg

	def genNetworkCfg(self, network: NetworkParams, *args, **kwargs):
		cfg = ""

		if network.ttl:
			cfg += "probe-ttl = " + str(network.ttl) + "\n"

		if network.osiLayer == OSILayer.IP:
			cfg += "iplayer = true\n"

		if network.adapterName:
			cfg += "interface =  " + str(network.adapterName) + "\n"

		if network.sender:
			sender = network.sender
			if sender.mac:
				cfg += "source-mac = " + sender.mac.format(mac_eui48) + "\n"

			if sender.ip:
				myIpv4Ip = None
				myIpv6Ip = None
				if not isinstance(myIp, tuple):
					if isinstance(myIp, IPv4Address):
						myIpv4Ip = myIp
					elif isinstance(myIp, IPv6Address):
						myIpv6Ip = myIp
				if myIpv4Ip:
					cfg += "adapter-ip = " + str(myIpv4Ip) + "\n"
				if myIpv6Ip:
					cfg += "ipv6-source-ip = " + str(myIpv6Ip) + "\n"

			if sender.portRange:
				sendPortRange = sender.portRange
				if isinstance(sendPortRange, range):
					rlen = sendPortRange.stop - sendPortRange.start
					sendPort = str(sendPortRange.start) + "-" + str(sendPortRange.stop)
				else:
					sendPort = str(sendPortRange)

				cfg += "source-port = " + sendPortRange + "\n"

		if network.gateway:
			gateway = network.gateway
			if gateway.mac:
				if not isinstance(gateway.mac, EUI):
					raise NotImplementedError("Zmap doesn't support separate ipv6 MACs for gateways")

				cfg += "gateway-mac = " + gateway.mac.format(mac_eui48) + "\n"

		return cfg

	def genResourceCfg(self, resource: ResourceConstraints, *args, **kwargs):
		cfg = ""

		if resource.rate:
			cfg += "rate = " + str(resource.rate) + "\n"

		if resource.waitTime:
			cfg += "cooldown-time = " + str(resource.waitTime) + "\n"

		if resource.retries:
			cfg += "probes = " + str(resource.retries) + "\n"

		if resource.bandwidth:
			cfg += "bandwidth = " + str(resource.bandwidth) + "\n"

		if resource.dryRun:
			cfg = "dryrun = true\n"

		reportMode2Filter = {
			ReportMode.closed: "success = 0",
			ReportMode.open: "success = 1",
			(ReportMode.closed | ReportMode.open): None,
		}

		reportMode = reportMode2Filter[resource.reportMode]

		if reportMode is not None:
			cfg += 'output-filter= "' + reportMode + '"\n'

		return cfg

	def genScanTypeCfg(self, scanTypes: typing.Iterable[ScanTypeParams], *args, **kwargs):
		if len(scanTypes) > 1:
			raise NotImplemented("This scanner doesn't support more than 1 scan type")

		scanType = scanTypes[0]

		cfg = "probe-module = " + getScanTypeStr(scanType) + "\n"

		return cfg

	def genInteractionCfg(self, format, outputFileName, outputFields, *args, **kwargs):
		return (
			"\n".join(
				(
					"output-file = " + str(outputFileName),
					"output-module = " + format,
					"output-fields = " + ",".join(outputFields),
				)
			)
			+ "\n"
		)

	def genTaskCfg(self, task: ScanTask, singleIpV4sFile=None, ipv4SubnetsFile=None, singleIpsV6File=None, *args, **kwargs):
		cfg = ""

		for p in task.ports:
			cfg += "target-port = " + str(p) + "\n"

		if task.excludes is not None:
			if isinstance(task.excludes, Path):
				cfg += "blocklist-file = " + str(task.excludes) + "\n"
			else:
				raise NotImplementedError("zmap accepts blacklist only in form of files")

		# for ip in task.ips:
		# 	cfg += "source-ip = " + str(ip) + "\n"

		if singleIpV4sFile:
			cfg += "list-of-ips-file = " + str(singleIpV4sFile) + "\n"
		if ipv4SubnetsFile:
			cfg += "allowlist-file = " + str(ipv4SubnetsFile) + "\n"

		if singleIpsV6File:
			cfg += "ipv6-target-file = " + str(singleIpsV6File) + "\n"
		return cfg

	def genCaptureCfg(self, capture: CaptureParams, *args, **kwargs):
		return ""


class ZMapBackend(Scanner):
	__slots__ = ("toolCmd",)

	META = ScannerMeta(
		name="zmap",
		types=tuple(supportedScanTypes),
		osiLayers=(OSILayer.Ethernet, OSILayer.IP),
		ipKinds=(IPv4Address, IPv4Network, IPv6Address, IPv6Network),
		scanOrientations=(ScanMatrix),
		acceptsInputsAsFile=True,
		responsesCaptureMethods=(),
	)

	def __init__(self, scanParams: ScanParams, toolCmd: typing.Union[str, Path] = "zmap"):
		super().__init__(scanParams)
		self.toolCmd = sh.Command(toolCmd)

	def __call__(self, task: ScanTask) -> ScanJob:
		if isinstance(task, ScanMatrix):
			ipv4sSingle = []
			ipv4sNetworks = []
			ipv6s = []
			for ip in task.ips:
				if isinstance(ip, IPv4Address):
					ipv4sSingle.append(ip)
				elif isinstance(ip, IPv4Network):
					ipv4sNetworks.append(ip)
				elif isinstance(ip, (IPv6Address, IPv6Network)):
					ipv6s.append(ip)
				else:
					raise ValueError("Unsupported IP type: ", repr(ip))

			if ipv4sSingle:
				sL = len(ipv4sSingle)
				nL = len(ipv4sNetworks)
				magicRecommendedValue = int(1e6)  # adviced in the --help

				print(sL < magicRecommendedValue, nL < magicRecommendedValue)
				if sL < magicRecommendedValue and nL < magicRecommendedValue:
					totalL = sL + nL
					Δ = totalL - magicRecommendedValue
					print(totalL, Δ, sL - Δ)
					additionalNetworks = [IPv4Network(e) for e in ipv4sSingle[: (sL - Δ)]]
					print(additionalNetworks)
					ipv4sNetworks += additionalNetworks
					ipv4sSingle = ipv4sSingle[(sL - Δ) :]

			singleIpV4sFileM = dummyCtx()
			ipv4SubnetsFileM = dummyCtx()
			singleIpV6sFileM = dummyCtx()

			print(ipv4sSingle, ipv4sNetworks, ipv6s)

			if ipv4sSingle:
				singleIpV4sFileM = MempipedPathRead("\n".join(map(str, ipv4sSingle)))

			if ipv4sNetworks:
				ipv4SubnetsFileM = MempipedPathRead("\n".join(map(str, ipv4sNetworks)))

			if ipv6s:
				singleIpV6sFileM = MempipedPathRead("\n".join(map(str, ipv6s)))

			cg = ZMapConfigGenerator()

			with singleIpV4sFileM as singleIpV4sFile:
				with ipv4SubnetsFileM as ipv4SubnetsFile:
					with singleIpV6sFileM as singleIpV6sFile:
						cfgText = cg(
							task,
							self.params,
							format="json",
							outputFileName="-",
							singleIpV4sFile=singleIpV4sFile,
							ipv4SubnetsFile=ipv4SubnetsFile,
							singleIpsV6File=singleIpV6sFile,
							pcapResponsesFile=None,
							outputFields=allOutputFields,
						)
						print(cfgText)
						# raise Exception
						with MempipedPathRead(cfgText) as cfgFile:
							res = self.toolCmd(config=cfgFile, _err=sys.stderr)

			return SynchronousJob(resultParser(res.stdout))
		else:
			raise NotImplementedError("zmap doesn't fit for per-host params")
