#!/usr/bin/env python
# -*- coding: utf-8 -*-

import socket
import struct
import sys
import logging

class IPv4Member(object):
	def __init__(self, ip, network, mask=None, log=None):
		self.IP = ip

		if not log:
			FORMAT = "%(asctime)-15s %(message)s"
			logging.basicConfig(format=FORMAT, level=10)
			self.log = logging.getLogger()
		else:
			self.log = log

		if not mask:
			try:
				self.NETWORK, cidr = network.split('/')
				self.CIDR = int(cidr)
			except (ValueError) as e:
				raise Exception(
					'neither cidr nor netmask provided. E: {0}'.format(e)
				)
		else:
			self.NETMASK = mask
			self.NETWORK = network

		self.write_log()
		self.translate_ip()
		self.translate_mask()
		self.is_member()

	def _gen_custom_attr(self):
		return [i for i in dir(self) if i.isupper()]

	def translate_ip(self):
		self.BIN_IP = socket.inet_aton(self.IP)
		self.INT_IP = struct.unpack('!L', self.BIN_IP)[0]

		self.write_log()

	def translate_mask(self):
		if not hasattr(self, 'NETMASK'):
			self.NETMASK = self.mask_from_cidr()

		self.BIN_NETMASK = socket.inet_aton(self.NETMASK)
		self.INT_NETMASK = struct.unpack('!L', self.BIN_NETMASK)[0]

		self.check_network()

		self.IP_INT_NETWORK_ADDR = (self.INT_IP & self.INT_NETMASK)
		self.IP_BIN_NETWORK_ADDR = struct.pack('!L', self.IP_INT_NETWORK_ADDR)
		self.IP_NETWORK_ADDR = socket.inet_ntoa(self.IP_BIN_NETWORK_ADDR)

		self.write_log()

	def check_network(self):
		bin_net = socket.inet_aton(self.NETWORK)
		int_net = struct.unpack('!L', bin_net)[0]
		int_new_net = (int_net & self.INT_NETMASK)

		if int_net == int_new_net:
			self.INT_NETWORK = int_net
			self.BIN_NETMASK = bin_net
		else:
			self.INT_NETWORK = int_new_net
			self.BIN_NETWORK = struct.pack('!L', self.INT_NETWORK)
			self.NETWORK = socket.inet_ntoa(self.BIN_NETWORK)


	def is_member(self):
		self.IS_MEMBER = True
		if self.IP_INT_NETWORK_ADDR - self.INT_NETWORK != 0:
			self.IS_MEMBER = False

		self.write_log()
	
	def mask_from_cidr(self):
		prefix_bits = 32 - self.CIDR
		x = (1<<32) - (1<<prefix_bits) # 255.255.255.255 - hosts
		return socket.inet_ntoa(struct.pack('!L', x))

	def write_log(self):
		string = ' - '.join(
			['%s: {%s}' % (i, i) for i in self._gen_custom_attr()]
		)
		self.log.info(string.format(**self.__dict__))

if __name__ == '__main__':
	try:
		ip = IPv4Member(*sys.argv[1:])
	except (Exception) as e:
		sys.stderr.write('{0}\n'.format(repr(e)))
