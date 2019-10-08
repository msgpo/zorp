#!/usr/bin/env python2.7

import unittest
import netaddr

from Zorp.Common import LoggerSingleton

from Zorp.Subnet import Subnet, InetSubnet, Inet6Subnet


class TestSubnet(unittest.TestCase):
    def test_create(self):
        # https://en.wikipedia.org/wiki/IPv6_address#Representation
        self.assertIsInstance(Subnet.create('2001:0db8:85a3:0000:0000:8a2e:0370:7334/128'), Inet6Subnet)
        self.assertIsInstance(Subnet.create('2001:db8:85a3:0:0:8a2e:370:7334/128'), Inet6Subnet)
        self.assertIsInstance(Subnet.create('2001:db8:85a3::8a2e:370:7334/128'), Inet6Subnet)
        self.assertIsInstance(Subnet.create('0:0:0:0:0:0:0:1/128'), Inet6Subnet)
        self.assertIsInstance(Subnet.create('0:0:0:0:0:0:0:0/0'), Inet6Subnet)
        self.assertIsInstance(Subnet.create('::1/128'), Inet6Subnet)
        self.assertIsInstance(Subnet.create('::/0'), Inet6Subnet)
        self.assertIsInstance(Subnet.create('::ffff:c000:0280/128'), Inet6Subnet)
        self.assertIsInstance(Subnet.create('::ffff:192.0.2.128/128'), Inet6Subnet)

        # https://en.wikipedia.org/wiki/IPv6_address#Special_addresses
        self.assertIsInstance(Subnet.create('::/0'), Inet6Subnet)
        self.assertIsInstance(Subnet.create('::/128'), Inet6Subnet)
        self.assertIsInstance(Subnet.create('::1/128'), Inet6Subnet)
        self.assertIsInstance(Subnet.create('::ffff:0:0/96'), Inet6Subnet)
        self.assertIsInstance(Subnet.create('::ffff:0:0:0/96'), Inet6Subnet)
        self.assertIsInstance(Subnet.create('64:ff9b::/96'), Inet6Subnet)
        self.assertIsInstance(Subnet.create('100::/64'), Inet6Subnet)
        self.assertIsInstance(Subnet.create('2001::/32'), Inet6Subnet)
        self.assertIsInstance(Subnet.create('2001:20::/28'), Inet6Subnet)
        self.assertIsInstance(Subnet.create('2001:db8::/32'), Inet6Subnet)
        self.assertIsInstance(Subnet.create('2002::/16'), Inet6Subnet)
        self.assertIsInstance(Subnet.create('fc00::/7'), Inet6Subnet)
        self.assertIsInstance(Subnet.create('fe80::/10'), Inet6Subnet)
        self.assertIsInstance(Subnet.create('ff00::/8'), Inet6Subnet)

        # https://en.wikipedia.org/wiki/IPv4#Special-use_addresses
        self.assertIsInstance(Subnet.create('0.0.0.0/8'), InetSubnet)
        self.assertIsInstance(Subnet.create('10.0.0.0/8'), InetSubnet)
        self.assertIsInstance(Subnet.create('100.64.0.0/10'), InetSubnet)
        self.assertIsInstance(Subnet.create('127.0.0.0/8'), InetSubnet)
        self.assertIsInstance(Subnet.create('169.254.0.0/16'), InetSubnet)
        self.assertIsInstance(Subnet.create('172.16.0.0/12'), InetSubnet)
        self.assertIsInstance(Subnet.create('192.0.0.0/24'), InetSubnet)
        self.assertIsInstance(Subnet.create('192.0.2.0/24'), InetSubnet)
        self.assertIsInstance(Subnet.create('192.88.99.0/24'), InetSubnet)
        self.assertIsInstance(Subnet.create('192.168.0.0/16'), InetSubnet)
        self.assertIsInstance(Subnet.create('198.18.0.0/15'), InetSubnet)
        self.assertIsInstance(Subnet.create('198.51.100.0/24'), InetSubnet)
        self.assertIsInstance(Subnet.create('203.0.113.0/24'), InetSubnet)
        self.assertIsInstance(Subnet.create('224.0.0.0/4'), InetSubnet)
        self.assertIsInstance(Subnet.create('240.0.0.0/4'), InetSubnet)
        self.assertIsInstance(Subnet.create('255.255.255.255/32'), InetSubnet)


if __name__ == '__main__':
    unittest.main()
