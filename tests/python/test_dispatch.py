# vim: ts=8 sts=4 expandtab autoindent

############################################################################
##
## Copyright (c) 2000-2015 BalaBit IT Ltd, Budapest, Hungary
## Copyright (c) 2015-2018 BalaSys IT Ltd, Budapest, Hungary
##
##
## This program is free software; you can redistribute it and/or modify
## it under the terms of the GNU General Public License as published by
## the Free Software Foundation; either version 2 of the License, or
## (at your option) any later version.
##
## This program is distributed in the hope that it will be useful,
## but WITHOUT ANY WARRANTY; without even the implied warranty of
## MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
## GNU General Public License for more details.
##
## You should have received a copy of the GNU General Public License along
## with this program; if not, write to the Free Software Foundation, Inc.,
## 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
##
############################################################################

from Zorp.Core import *
from Zorp.Proxy import Proxy
from Zorp.Zorp import quit

import unittest

config.options.kzorp_enabled = FALSE

class TestDispatcher(unittest.TestCase):

    def setUp(self):
        Service('test', Proxy)

    def tearDown(self):
        import Zorp.Globals
        Zorp.Globals.services.clear()

    def test_keyword_args(self):
        """Test keyword argument that is processed by the C code."""
        Dispatcher(DBSockAddr(SockAddrInet('0.0.0.0', 1999), protocol=ZD_PROTO_TCP), 'test', transparent=TRUE)
        Dispatcher(DBIface('eth0', 1999, protocol=ZD_PROTO_TCP), 'test', transparent=TRUE)
        Dispatcher(DBIfaceGroup(100, 1999, protocol=ZD_PROTO_TCP), 'test', transparent=TRUE)

        ZoneDispatcher(DBSockAddr(SockAddrInet('0.0.0.0', 1999), protocol=ZD_PROTO_TCP), {'all': 'test'}, transparent=TRUE)
        ZoneDispatcher(DBIface('eth0', 1999, protocol=ZD_PROTO_TCP), {'all': 'test'}, transparent=TRUE)
        ZoneDispatcher(DBIfaceGroup(100, 1999, protocol=ZD_PROTO_TCP), {'all': 'test'}, transparent=TRUE)

        CSZoneDispatcher(DBSockAddr(SockAddrInet('0.0.0.0', 1999), protocol=ZD_PROTO_TCP), {('all', 'all'): 'test'}, transparent=TRUE)
        CSZoneDispatcher(DBIface('eth0', 1999, protocol=ZD_PROTO_TCP), {('all', 'all'): 'test'}, transparent=TRUE)
        CSZoneDispatcher(DBIfaceGroup(100, 1999, protocol=ZD_PROTO_TCP), {('all', 'all'): 'test'}, transparent=TRUE)

    def test_constructors(self):
        """No keyword arguments."""
        Dispatcher(DBSockAddr(SockAddrInet('0.0.0.0', 1999), protocol=ZD_PROTO_TCP), 'test')
        Dispatcher(DBIface('eth0', 1999, protocol=ZD_PROTO_TCP), 'test')

        ZoneDispatcher(DBSockAddr(SockAddrInet('0.0.0.0', 1999), protocol=ZD_PROTO_TCP), {'all': 'test'})
        ZoneDispatcher(DBIface('eth0', 1999, protocol=ZD_PROTO_TCP), {'all': 'test'})

        CSZoneDispatcher(DBSockAddr(SockAddrInet('0.0.0.0', 1999), protocol=ZD_PROTO_TCP), {('all', 'all'): 'test'})
        CSZoneDispatcher(DBIface('eth0', 1999, protocol=ZD_PROTO_TCP), {('all', 'all'): 'test'})

def zorp():
    unittest.main(argv=('/'))

# Local Variables:
# mode: python
# indent-tabs-mode: nil
# python-indent: 4
# End:
