import typing
from secrets import token_bytes
from struct import Struct

_cache = {}


def randTuple(spec: str) -> typing.Tuple[typing.Any, ...]:
	s = _cache.get(spec, None)
	if s is None:
		_cache[spec] = s = Struct("=" + spec)
	return s.unpack(token_bytes(s.size))


def randInt(spec):
	assert len(spec) == 1
	return randTuple(spec)[0]
