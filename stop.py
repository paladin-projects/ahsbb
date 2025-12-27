import sys
from kaitaistruct import KaitaiStruct

class UnknownMagic(Exception):
	pass

class Stop(KaitaiStruct):
	def decode(self, unknown1):
		raise UnknownMagic()
