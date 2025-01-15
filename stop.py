import sys
from kaitaistruct import KaitaiStruct

class UnknownMagic(Exception):
	def __init__(self, io):
		self._io = io._io

class Stop(KaitaiStruct):
	def decode(self, unknown1):
		raise UnknownMagic(self)
