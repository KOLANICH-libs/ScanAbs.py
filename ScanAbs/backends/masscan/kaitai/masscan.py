# This is a generated file! Please edit source .ksy file and use kaitai-struct-compiler to rebuild

from enum import Enum

import kaitaistruct
from kaitaistruct import BytesIO, KaitaiStream, KaitaiStruct
from pkg_resources import parse_version

if parse_version(kaitaistruct.__version__) < parse_version("0.9"):
	raise Exception("Incompatible Kaitai Struct Python API: 0.9 or later is required, but you have %s" % (kaitaistruct.__version__))

from . import vlq_base128_le
from .protocol_body import ProtocolBody


class Masscan(KaitaiStruct):
	"""
    .. seealso::
       Source - https://github.com/robertdavidgraham/masscan/blob/2895fa0acfe45983a3e9b2bbfadf25934c8d2c65/src/out-binary.c


    .. seealso::
       Source - https://github.com/robertdavidgraham/masscan/blob/2895fa0acfe45983a3e9b2bbfadf25934c8d2c65/src/in-binary.c"""

	class AppProto(Enum):
		none = 0
		heur = 1
		ssh1 = 2
		ssh2 = 3
		http = 4
		ftp = 5
		dns_version_bind = 6
		snmp = 7
		nbt_stat = 8
		ssl3 = 9
		smb = 10
		smtp = 11
		pop3 = 12
		imap4 = 13
		udp_zero_access = 14
		x509_cert = 15
		html_title = 16
		html_full = 17
		ntp = 18
		vuln = 19
		heartbleed = 20
		ticketbleed = 21
		vnc_rfb = 22
		safe = 23
		memcached = 24
		scripting = 25
		versioning = 26
		coap = 27
		telnet = 28
		rdp = 29
		http_server = 30
		end_of_list = 31

	def __init__(self, _io, _parent=None, _root=None):
		self._io = _io
		self._parent = _parent
		self._root = _root if _root else self
		self._read()

	def _read(self):
		self._raw_header = self._io.read_bytes(99)
		_io__raw_header = KaitaiStream(BytesIO(self._raw_header))
		self.header = Masscan.Header(_io__raw_header, self, self._root)
		self.records = []
		i = 0
		while True:
			_ = Masscan.Record(self._io, self, self._root)
			self.records.append(_)
			if (self._io.size() - self._io.pos()) <= self.header_size:
				break
			i += 1
		self.footer = Masscan.Footer(self._io, self, self._root)

	class Header(KaitaiStruct):
		def __init__(self, _io, _parent=None, _root=None):
			self._io = _io
			self._parent = _parent
			self._root = _root if _root else self
			self._read()

		def _read(self):
			self.signature = (self._io.read_bytes_term(47, False, True, True)).decode(u"ascii")
			if not self.signature == u"masscan":
				raise kaitaistruct.ValidationNotEqualError(u"masscan", self.signature, self._io, u"/types/header/seq/0")
			self.version_str = (self._io.read_bytes_term(10, False, True, True)).decode(u"ascii")
			self.metadata_str = (KaitaiStream.bytes_terminate(self._io.read_bytes_full(), 0, False)).decode(u"ascii")

	class Footer(KaitaiStruct):
		def __init__(self, _io, _parent=None, _root=None):
			self._io = _io
			self._parent = _parent
			self._root = _root if _root else self
			self._read()

		def _read(self):
			self.signature = (self._io.read_bytes_term(47, False, True, True)).decode(u"ascii")
			if not self.signature == self._parent.header.signature:
				raise kaitaistruct.ValidationNotEqualError(self._parent.header.signature, self.signature, self._io, u"/types/footer/seq/0")
			self.version_str = (self._io.read_bytes_term(0, False, True, True)).decode(u"ascii")
			if not self.version_str == self._parent.header.version_str:
				raise kaitaistruct.ValidationNotEqualError(self._parent.header.version_str, self.version_str, self._io, u"/types/footer/seq/1")
			self.metadata_str = (KaitaiStream.bytes_terminate(self._io.read_bytes_full(), 0, False)).decode(u"ascii")

	class Record(KaitaiStruct):
		class Type(Enum):
			status_open = 1
			status_closed = 2
			banner3 = 3
			banner4 = 4
			banner_4_1 = 5
			status2_open = 6
			status2_closed = 7
			banner9 = 9
			status6_open = 10
			status6_closed = 11
			banner6 = 13
			m = 109

		def __init__(self, _io, _parent=None, _root=None):
			self._io = _io
			self._parent = _parent
			self._root = _root if _root else self
			self._read()

		def _read(self):
			self.type_raw = vlq_base128_le.VlqBase128Le(self._io)
			self.length = vlq_base128_le.VlqBase128Le(self._io)
			_on = self.type
			if _on == Masscan.Record.Type.banner6:
				self._raw_payload = self._io.read_bytes(self.length.value)
				_io__raw_payload = KaitaiStream(BytesIO(self._raw_payload))
				self.payload = Masscan.Record.MasscanRecord(True, False, False, True, True, True, _io__raw_payload, self, self._root)
			elif _on == Masscan.Record.Type.banner3:
				self._raw_payload = self._io.read_bytes(self.length.value)
				_io__raw_payload = KaitaiStream(BytesIO(self._raw_payload))
				self.payload = Masscan.Record.MasscanRecord(True, True, False, True, False, False, _io__raw_payload, self, self._root)
			elif _on == Masscan.Record.Type.status2_closed:
				self._raw_payload = self._io.read_bytes(self.length.value)
				_io__raw_payload = KaitaiStream(BytesIO(self._raw_payload))
				self.payload = Masscan.Record.MasscanRecord(False, True, True, False, True, True, _io__raw_payload, self, self._root)
			elif _on == Masscan.Record.Type.status_open:
				self._raw_payload = self._io.read_bytes(self.length.value)
				_io__raw_payload = KaitaiStream(BytesIO(self._raw_payload))
				self.payload = Masscan.Record.MasscanRecord(True, False, True, False, True, True, _io__raw_payload, self, self._root)
			elif _on == Masscan.Record.Type.status6_closed:
				self._raw_payload = self._io.read_bytes(self.length.value)
				_io__raw_payload = KaitaiStream(BytesIO(self._raw_payload))
				self.payload = Masscan.Record.MasscanRecord(False, False, True, False, True, True, _io__raw_payload, self, self._root)
			elif _on == Masscan.Record.Type.status6_open:
				self._raw_payload = self._io.read_bytes(self.length.value)
				_io__raw_payload = KaitaiStream(BytesIO(self._raw_payload))
				self.payload = Masscan.Record.MasscanRecord(True, False, True, False, True, True, _io__raw_payload, self, self._root)
			elif _on == Masscan.Record.Type.banner4:
				self._raw_payload = self._io.read_bytes(self.length.value)
				_io__raw_payload = KaitaiStream(BytesIO(self._raw_payload))
				self.payload = Masscan.Record.MasscanRecord(True, True, False, True, False, True, _io__raw_payload, self, self._root)
			elif _on == Masscan.Record.Type.status2_open:
				self._raw_payload = self._io.read_bytes(self.length.value)
				_io__raw_payload = KaitaiStream(BytesIO(self._raw_payload))
				self.payload = Masscan.Record.MasscanRecord(True, True, True, False, True, True, _io__raw_payload, self, self._root)
			elif _on == Masscan.Record.Type.status_closed:
				self._raw_payload = self._io.read_bytes(self.length.value)
				_io__raw_payload = KaitaiStream(BytesIO(self._raw_payload))
				self.payload = Masscan.Record.MasscanRecord(False, False, True, False, True, True, _io__raw_payload, self, self._root)
			elif _on == Masscan.Record.Type.banner9:
				self._raw_payload = self._io.read_bytes(self.length.value)
				_io__raw_payload = KaitaiStream(BytesIO(self._raw_payload))
				self.payload = Masscan.Record.MasscanRecord(True, True, False, True, True, True, _io__raw_payload, self, self._root)
			else:
				self.payload = self._io.read_bytes(self.length.value)

		class MasscanRecord(KaitaiStruct):
			def __init__(
				self,
				is_open,
				old,
				has_reason,
				app_proto_present,
				has_ttl,
				has_ip_proto,
				_io,
				_parent=None,
				_root=None,
			):
				self._io = _io
				self._parent = _parent
				self._root = _root if _root else self
				self.is_open = is_open
				self.old = old
				self.has_reason = has_reason
				self.app_proto_present = app_proto_present
				self.has_ttl = has_ttl
				self.has_ip_proto = has_ip_proto
				self._read()

			def _read(self):
				_on = self.old
				if _on:
					self._is_le = True
				elif _on == False:
					self._is_le = False
				if not hasattr(self, "_is_le"):
					raise kaitaistruct.UndecidedEndiannessError("/types/record/types/masscan_record")
				elif self._is_le:
					self._read_le()
				elif self._is_le == False:
					self._read_be()

			def _read_le(self):
				self.timestamp = self._io.read_u4le()
				if self.old:
					self.ipv4 = self._io.read_bytes(4)

				if self.has_ip_proto:
					self.ip_proto = KaitaiStream.resolve_enum(ProtocolBody.ProtocolEnum, self._io.read_u1())

				self.port = self._io.read_u2le()
				if self.app_proto_present:
					self.app_proto = KaitaiStream.resolve_enum(Masscan.AppProto, self._io.read_u2le())

				if self.has_reason:
					self.reason = self._io.read_u1()

				if self.has_ttl:
					self.ttl = self._io.read_u1()

				if not (self.old):
					self.ip_with_version = Masscan.Record.SwitcheableIpVersion(self._io, self, self._root)

			def _read_be(self):
				self.timestamp = self._io.read_u4be()
				if self.old:
					self.ipv4 = self._io.read_bytes(4)

				if self.has_ip_proto:
					self.ip_proto = KaitaiStream.resolve_enum(ProtocolBody.ProtocolEnum, self._io.read_u1())

				self.port = self._io.read_u2be()
				if self.app_proto_present:
					self.app_proto = KaitaiStream.resolve_enum(Masscan.AppProto, self._io.read_u2be())

				if self.has_reason:
					self.reason = self._io.read_u1()

				if self.has_ttl:
					self.ttl = self._io.read_u1()

				if not (self.old):
					self.ip_with_version = Masscan.Record.SwitcheableIpVersion(self._io, self, self._root)

			@property
			def ip_addr(self):
				if hasattr(self, "_m_ip_addr"):
					return self._m_ip_addr if hasattr(self, "_m_ip_addr") else None

				self._m_ip_addr = self.ipv4 if self.old else self.ip_with_version.addr
				return self._m_ip_addr if hasattr(self, "_m_ip_addr") else None

		class SwitcheableIpVersion(KaitaiStruct):
			def __init__(self, _io, _parent=None, _root=None):
				self._io = _io
				self._parent = _parent
				self._root = _root if _root else self
				self._read()

			def _read(self):
				self.version = self._io.read_u1()
				if not self.version == 6:
					raise kaitaistruct.ValidationNotEqualError(6, self.version, self._io, u"/types/record/types/switcheable_ip_version/seq/0")
				self.addr = self._io.read_bytes(16)

		@property
		def type(self):
			if hasattr(self, "_m_type"):
				return self._m_type if hasattr(self, "_m_type") else None

			self._m_type = KaitaiStream.resolve_enum(Masscan.Record.Type, self.type_raw.value)
			return self._m_type if hasattr(self, "_m_type") else None

	@property
	def header_size(self):
		if hasattr(self, "_m_header_size"):
			return self._m_header_size if hasattr(self, "_m_header_size") else None

		self._m_header_size = 99
		return self._m_header_size if hasattr(self, "_m_header_size") else None
