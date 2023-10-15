from ipaddress import ip_address

import netifaces
from plumbum import cli

from .backends import backends
from .core.ScanTask import PortsScanMatrix, ScanMatrix

from netaddr import EUI
from ipaddress import IPv4Address, IPv6Address


from .core.scantypes import parseScanTypeFromString


class CLI(cli.Application):
	backend = cli.SwitchAttr(["-B", "--backend"], cli.Set(*backends), default="zmap", help="The backend", argname="Backend_name", group="General")

	scanTypes = cli.SwitchAttr(["--scan-type"], str, default="tcp:syn", help="The scan types", argname="scan_types", group="Task")
	excludesFile = cli.SwitchAttr(["-b", "--excludefile", "--blacklist-file"], cli.ExistingFile, default=None, help="File of hosts and networks that must not be scanned", argname="blacklists_file", group="Task")
	includesFile = cli.SwitchAttr(["-iL", "--includefile", "--whitelist-file"], cli.ExistingFile, default=None, help="File of hosts and networks that must be scanned", argname="whitelists file", group="Task")


	reportMode = cli.SwitchAttr(["--reportMode"], cli.Set("open", "closed"), default="open", help="Which results to report. Allows to report only open or only closed ports.", argname="mode", group="Resource")
	rate = cli.SwitchAttr(["--rate"], int, default=None, help="Max rate of scan.", argname="rate", group="Resource")
	bandwidth = cli.SwitchAttr(["--bandwidth"], int, default=None, help="Max speed of scan.", argname="speed", group="Resource")
	retries = cli.SwitchAttr(["-P", "--retries", "--probes"], int, default=1, help="Count of probes per port.", argname="#probes", group="Resource")
	dryRun = cli.SwitchAttr(["-d", "--dryrun", "--offline"], int, default=False, help="Whether don't scan, just run a scanner with a built-in simulation.", group="Resource")
	waitTime = cli.SwitchAttr(["--wait", "--cooldown-time"], int, default=10, help="How long to wait for responses after scan end", argname="seconds", group="Resource")
	timeout = cli.SwitchAttr(["--timeout"], int, default=1, help="Stop track responses from an endpoint after this amount of time", argname="seconds", group="Resource")

	v4_sender_ip = cli.SwitchAttr(["-S", "--adapter-ip", "--source-ip"], str, default=None, help="Our IPv4 address, real or spoofed", argname="IPv4", group="Sender v4")
	v4_sender_port = cli.SwitchAttr(["-s", "-g", "--adapter-port", "--source-port"], str, default=None, help="Our port we scan from. Allows to bypass some firewalls.", argname="port", group="Sender v4")
	v4_sender_mac = cli.SwitchAttr(["--adapter-mac", "--spoof-mac"], str, default=None, help="Our MAC address, real or spoofed", argname="MAC addr", group="Sender v4")

	v6_sender_ip = cli.SwitchAttr(["--ipv6-source-ip"], int, default=None, help="Our IPv6 address, real or spoofed", argname="IPv6", group="Sender v6")
	# v6_sender_port = cli.SwitchAttr(["", ""], int, default=, group = "Sender v6")
	# v6_sender_mac = cli.SwitchAttr(["", ""], int, default=, group = "Sender v6")

	v4_gateway_mac = cli.SwitchAttr(["-G", "--gateway-mac", "--router-mac", "--router-mac-ipv4"], int, default=None, help="Our gateway (for IPv4) MAC address", argname="MAC", group="Gateway v4")

	v6_gateway_mac = cli.SwitchAttr(["--router-mac-ipv6"], int, default=None, help="Our gateway (for IPv6) MAC address", argname="MAC", group="Gateway v6")

	osiLayer = cli.SwitchAttr(["-L", "--layer"], int, default=None, help="OSI/ISO layer on which scanner crafts and sends packets. To send packets on L2, elevation is required. To send on L3 it is highly desireable. Also sending on L3 allows to work through L3 tunnels, like WireGuard", argname="level", group="Network")
	ttl = cli.SwitchAttr(["--ttl"], int, default=None, help="TTL of packets sent.", argname="TTL", group="Network")
	adapterName = cli.SwitchAttr(["-i", "--interface", "--adapter"], cli.Set(*netifaces.interfaces()), default=None, help="Select the local adapter through which to send.", argname="adapter_name")

	countOfShards = cli.SwitchAttr(["--shardCount", "--shards"], int, default=1, help="Utilize scanner built-in sharding. Total count of shards.", argname="#shards", group="Sharding")
	currentShard = cli.SwitchAttr(["--shard"], int, default=1, help="№ of current shard", argname="current_shard", group="Sharding")
	seed = cli.SwitchAttr(["-e", "--seed"], int, default=None, help="RNG seed", argname="seed", group="Sharding")

	def main(self, hosts="192.168.2.1", ports="443"):
		backendCtor = backends[self.backend]

		hosts = [ip_address(host) for host in hosts.split(",")]
		ports = [int(port) for port in ports.split(",")]

		from .core.ScanParams import CaptureParams, DeviceParams, DistributionParams, NetworkParams, ResourceConstraints, ScanParams

		params = ScanParams()

		scanTypes = self.scanTypes
		scanTypes = scanTypesRaw.split(",")
		scanTypes = [self.parseScanType(s) for s in scanTypesRaw]

		# params.scanTypes

		params.network.osiLayer
		params.network.ttl = self.ttl
		params.network.adapterName = self.adapterName

		if v4_sender_ip:
			params.network.sender.v4.l3.ip = IPv4Address(v4_sender_ip)

		params.network.sender.v4.l3.port = v4_sender_port
		if v4_sender_mac:
			params.network.sender.v4.l2.mac = EUI(v4_sender_mac)

		if v6_sender_ip:
			params.network.sender.v6.l3.ip = IPv6Address(v6_sender_ip)
		# params.network.sender.v6.l3.port = v6_sender_port
		# params.network.sender.v6.l2.mac = EUI(v6_sender_mac)

		if v4_gateway_mac:
			params.network.gateway.v4.mac = EUI(v4_gateway_mac)
		if v6_gateway_mac:
			params.network.gateway.v6.mac = EUI(v6_gateway_mac)

		params.resource.bandwidth = self.bandWidth
		params.resource.dryRun = self.dryRun
		params.resource.rate = self.rate
		params.resource.reportMode
		params.resource.retries = self.retries
		params.resource.waitTime = self.waitTime

		params.distribution.countOfShards = self.countOfShards
		params.distribution.currentShard = self.currentShard
		params.distribution.seed = self.seed

		# params.capture.banners
		# params.capture.pcapResponsesFile

		backend = backendCtor(params)

		res = backend(ScanMatrix(hosts, PortsScanMatrix(ports))).getResults()
		print(res)


if __name__ == "__main__":
	CLI.run()
