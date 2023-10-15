from .masscan import MasscanBackend
from .zmap import ZMapBackend

backends = (MasscanBackend, ZMapBackend)
backends = {b.META.name: b for b in backends}
