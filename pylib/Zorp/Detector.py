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
"""
<module maturity="stable">
  <summary>
    Module defining interface to the Detectors.
  </summary>
  <description>
  <para>
    Detectors can be used to determine if the traffic in the incoming
    connection uses a particular protocol (for example, HTTP, SSH),
    or if it has other specific characteristics (for example, it uses
    SSL encryption with a specific certificate). Zorp can detect such
    characteristics of the traffic, and start a specific service to
    inspect the traffic (for example, start a specific HttpProxy for
    HTTP traffic, and so on).
  </para>
  </description>
</module>
"""

import enum
import re
from OpenSSL.crypto import FILETYPE_PEM, FILETYPE_ASN1, load_certificate, dump_certificate
from Zorp import *
from Common import TLS_ACCOUNTING
from Exceptions import MatcherException
from Matcher import getMatcher
import struct
import os

class DetectorPolicy(object):
    """<class maturity="stable" type="detectorpolicy">
      <summary>
        Class encapsulating a Detector which can be used by a name.
      </summary>
      <description>
        <para>
        DetectorPolicy instances are reusable detectors that contain configured
        instances of the detector classes (for example, HttpDetector, SshDetector)
        that detect if the traffic uses a particular protocol, or a
        particular certificate in an SSL/TLS connection.
        DetectorPolicy instances can be used in the <parameter>detect</parameter>
        option of firewall rules.
        For examples, see the specific detector classes.
        </para>
      </description>
      <metainfo>
        <attributes/>
      </metainfo>
    </class>
    """
    def __init__(self, name, detector):
        """<method internal="yes">
        <metainfo>
          <arguments>
            <argument maturity="stable">
              <name>detector</name>
              <type>
                <class filter="detector" instance="yes"/>
              </type>
              <description>The encapsulated Detector</description>
            </argument>
            <argument maturity="stable">
              <name>name</name>
              <type>
                <string/>
              </type>
              <description>The name of the Detector</description>
            </argument>
          </arguments>
        </metainfo>
        </method>
        """
        self.name = name
        self.detector = detector
        if Globals.detectors.has_key(name):
            raise ValueError, "Duplicate detector policy: %s" % name
        Globals.detectors[name] = self

    def detect(self, side, data):
        """
        <method internal="yes">
        </method>
        """
        return self.detector.detect(side, data)

class AbstractDetector(object):
    """
    <class maturity="stable" abstract="yes">
      <summary>
        Class encapsulating the abstract detector.
      </summary>
      <description>
        <para>
          This abstract class encapsulates a detector that
          determines whether the traffic in a connection belongs to a
          particular protocol.
        </para>
      </description>
      <metainfo>
        <attributes/>
      </metainfo>
    </class>
    """

    def __init__(self):
        """
        <method internal="yes">
          <summary>
            Constructor to initialize an AbstractDetector instance.
          </summary>
          <description>
            This constructor initializes an AbstractDetector instance. Currently it
            does nothing.
          </description>
          <metainfo>
            <arguments/>
          </metainfo>
        </method>
        """
        self.server_side_protocol = False
        pass

    def detect(self, side, data):
        """
        <method internal="yes">
          <summary>
            Virtual function to detect a protocol
          </summary>
          <description>
            <para>
              Description...
            </para>
            <para>
              Description2...
            </para>
          </description>
          <metainfo>
            <arguments>
              <argument maturity="stable">
                <name>side</name>
                <type></type>
                <description>client or server side</description>
              </argument>
              <argument maturity="stable">
                <name>data</name>
                <type></type>
                <description>protocol data</description>
              </argument>

            </arguments>
          </metainfo>
        </method>
        """
        raise NotImplementedError


class DetectResultType(enum.IntEnum):
    """<class internal="yes"/>"""
    NOMATCH = 0
    MATCH = 1
    UNDECIDED = 2
    COPY_CLIENT = 3


class DetectResult(object):
    """<class internal="yes"/>"""
    def __init__(self, result, bytes_to_copy = 0):
        self.result = result
        self.bytes_to_copy = bytes_to_copy


class HttpDetector(AbstractDetector):
    """
    <class maturity="stable">
      <summary>
        Class encapsulating a Detector that determines if the traffic uses
        the HTTP protocol
      </summary>
      <description>
        <para>
          This Detector determines if the traffic uses the HTTP protocol,
          and rejects any other protocol.
        </para>
        <example>
          <title>HttpDetector example</title>
          <para>The following example defines a DetectorPolicy that detects
          HTTP traffic.</para>
          <synopsis>DetectorPolicy(name="http", detector=HttpDetector()</synopsis>
        </example>
      </description>
      <metainfo>
        <attributes>
          <attribute maturity="stable">
            <name>match</name>
            <type></type>
            <description>A list of compiled regular expressions which result in a positive match.
            If the traffic matches this regular expression, it is regarded as HTTP traffic.
            Default value: <parameter>[OPTIONS|GET|HEAD|POST|PUT|DELETE|TRACE|CONNECT] + ".*HTTP/1."</parameter>
            </description>
          </attribute>
          <attribute maturity="stable">
            <name>ignore</name>
            <type></type>
            <description>A list of compiled regular expressions which should be ignored when
            detecting the traffic type. By default, this list is empty.
            </description>
          </attribute>
        </attributes>
      </metainfo>
    </class>
    """

    def __init__(self, **kw):
        """
        <method maturity="stable">
          <summary>
            Constructor to initialize a HttpDetector instance.
          </summary>
          <description>
            <para>
              This constructor initializes a HttpDetector instance
            </para>
          </description>
          <metainfo>
            <arguments/>
          </metainfo>
        </method>
        """
        super(HttpDetector, self).__init__()
        http_methods = "[OPTIONS|GET|HEAD|POST|PUT|DELETE|TRACE|CONNECT]"

        self._p = re.compile(http_methods + ".*HTTP/1.")

    def detect(self, side, data):
        """
        <method internal="yes">
          <summary>
            Function to determine wheter the given data can be recognised as Http protocol.
          </summary>
          <description>
            <para>
              Description...
            </para>
          </description>
          <metainfo>
            <arguments>
              <argument maturity="stable">
                <name>side</name>
                <type></type>
                <description>client or server side</description>
              </argument>
              <argument maturity="stable">
                <name>data</name>
                <type></type>
                <description>protocol data</description>
              </argument>
            </arguments>
          </metainfo>
        </method>
        """

        if side == ZEndpoint.EP_CLIENT and self._p.match(data):
            log(None, CORE_DEBUG, 6, "HTTP protocol found;")
            return DetectResult(DetectResultType.MATCH)

        return DetectResult(DetectResultType.NOMATCH)

class CertDetector(AbstractDetector):
    """
    <class maturity="stable">
      <summary>
        Class encapsulating a Detector that determines if an SSL/TLS-encrypted
        connection uses the specified certificate
      </summary>
      <description>
        <para>
          This Detector determines if an SSL/TLS-encrypted
          connection uses the specified certificate,
          and rejects any other protocols and certificates.
        </para>
        <example>
          <title>CertDetector example</title>
          <para>The following example defines a DetectorPolicy that detects
          if the traffic is SSL/TLS-encrypted, and uses the certificate
          specified.</para>
          <synopsis>
          mycertificate="-----BEGIN CERTIFICATE-----
MIIEdjCCA16gAwIBAgIIQ7Xu3Mwnk+4wDQYJKoZIhvcNAQEFBQAwSTELMAkGA1UE
BhMCVVMxEzARBgNVBAoTCkdvb2dsZSBJbmMxJTAjBgNVBAMTHEdvb2dsZSBJbnRl
cm5ldCBBdXRob3JpdHkgRzIwHhcNMTQwMTI5MTQwNTM3WhcNMTQwNTI5MDAwMDAw
WjBoMQswCQYDVQQGEwJVUzETMBEGA1UECAwKQ2FsaWZvcm5pYTEWMBQGA1UEBwwN
TW91bnRhaW4gVmlldzETMBEGA1UECgwKR29vZ2xlIEluYzEXMBUGA1UEAwwOd3d3
Lmdvb2dsZS5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCkeHmm
eYY7uMMRxKg14NPx8zFtD/VmUI2b4FdQYgD8AuRifA+fqvxicEki7Td1SrZ4zldn
AjbAS+fC0eQji8foJTosrkXgQgv5ds0+8lU3dooVXoqemeJKUihzI/h+7cf1287/
7EbMI5RaDBUPTHmZHeDtk38XUYsBrS93nICq4VDUAxy2BKsGSS2l9wRvl4fhdDDm
guQ5cRDKn/pqdYEqAqxFVEjamwjcUWSBsWlqSn37fI9s/MZDCzfMwz6AheFMrRNL
0oJ2Y3cVdBxiDVdqjGS+AG5qIUz/AsvHNL3JEsa55OSrMFubCPCzYDMAVLKziqZX
5G25c0e/qh0bSK4/AgMBAAGjggFBMIIBPTAdBgNVHSUEFjAUBggrBgEFBQcDAQYI
KwYBBQUHAwIwGQYDVR0RBBIwEIIOd3d3Lmdvb2dsZS5jb20waAYIKwYBBQUHAQEE
XDBaMCsGCCsGAQUFBzAChh9odHRwOi8vcGtpLmdvb2dsZS5jb20vR0lBRzIuY3J0
MCsGCCsGAQUFBzABhh9odHRwOi8vY2xpZW50czEuZ29vZ2xlLmNvbS9vY3NwMB0G
A1UdDgQWBBR1IOrR+bm3NNXp5DWKruhkxnMrpDAMBgNVHRMBAf8EAjAAMB8GA1Ud
IwQYMBaAFErdBhYbvPZotXb1gba7Yhq6WoEvMBcGA1UdIAQQMA4wDAYKKwYBBAHW
eQIFATAwBgNVHR8EKTAnMCWgI6Ahhh9odHRwOi8vcGtpLmdvb2dsZS5jb20vR0lB
RzIuY3JsMA0GCSqGSIb3DQEBBQUAA4IBAQA6j9oPKE5k/FX5sbLY4p7xsnltndHD
N1oyzmb8+cmke6W/eFHsY0g+zUeUBW3zb0EMBnNXWNTCB1aVIcRGe8GUDDAnAzSX
MQBeBisNb69kn2untS7RblL83+8H787RsLeXucahr3kCoc61oTemI0HEI43ODtVI
uFEDNJDE1wqsHkdZecnNS29IZySpK2skr3rH7qUkbP1lkzbFvsnFUyp3AJS4ib9+
4xPr65GQfUi/8vgoSVvOy5Y3rT/U3CtI9tPoDSZTYGTl64LDxJa8dEGYmTKHgjyJ
HmbKzes13N/BN18XUlvTnjEaifQXvJj9ypqcMHUFPjkqwI1HSyb1iRth
-----END CERTIFICATE-----"
          DetectorPolicy(name="MyCertDetector", detector=CertDetector(certificate=mycertificate)</synopsis>
        </example>
      </description>
      <metainfo>
        <attributes>
          <attribute maturity="stable">
            <name>certificate</name>
            <type></type>
            <description>The certificate to detect in PEM format.
            You can use the certificate directly, or store it in a file and
            reference the file with full path, for example,
            <parameter>DetectorPolicy(name="MyCertDetector", detector=CertDetector(certificate=("/etc/key.d/mysite/cert.pem", )))</parameter>
            </description>
          </attribute>
       </attributes>
      </metainfo>
    </class>
    """

    def __init__(self, certificate):
        """
        <method maturity="stable">
          <summary>
            Constructor to initialize a CertDetector instance.
          </summary>
          <description>
            <para>
              This constructor initializes a CertDetector instance
            </para>
          </description>
          <metainfo>
            <arguments>
              <argument maturity="stable">
                <name>certificate</name>
                <type>
                  <certificate cert="yes" key="yes"/>
                </type>
                <description>The certificate in PEM format.
                This must contain either the certificate as a string, or
                a full pathname to a file containing the certificate.
                </description>
              </argument>
            </arguments>
          </metainfo>
        </method>
        """

        super(CertDetector, self).__init__()
        self._handshake = chr(0x16) #Handshake protocol
        self._version_major = chr(0x03)
        self._version_minor = map(chr, [0, 0x01, 0x02, 0x03])
        self._handshake_type = chr(0x0b) #Cerficate
        self._client_hello_type = chr(0x01) #Client Hello
        self._server_hello_type = chr(0x02) #Server Hello
        self._server_detect_length = 12 #12 bytes needed from the server before the certificate
        self._client_detect_length = 11 #11 bytes needed from the client to detect Client Hello
        self._client_hello_sent = False
        self._cert = certificate
        if type(certificate) is tuple:
            if not os.path.isfile(certificate[0]):
                raise ValueError, "The certificate parameter should be either a string (containing the certificate in PEM format) or a tuple containing the filename (the file should exist and must be readable)."
            f = open(certificate[0], 'r')
            self._cert = f.read()
            f.close()

        pass

    def detect(self, side, data):
        """<method internal="yes"/>"""

        if side == ZEndpoint.EP_CLIENT:
            log(None, CORE_DEBUG, 6, "CLIENT_SIDE - Starting search for Client Hello")
            return self._detect_client(data)

        elif side == ZEndpoint.EP_SERVER:
            if not self._client_hello_sent:
                log(None, CORE_DEBUG, 6, "SERVER_SIDE - Client Hello is not sent yet by the client")
                return DetectResult(DetectResultType.NOMATCH)

            log(None, CORE_DEBUG, 6, "SERVER_SIDE - Starting search for Certificate")
            return self._detect_server(data)
        else:
            raise ValueError, "Side must be either Client or Server; side='%d'" % (side, )

    def _detect_client(self, data):
        """<method internal="yes"/>"""
        # NOTE: Implement fragmantation parsing
        if len(data) < self._client_detect_length:
            log(None, CORE_DEBUG, 6, "CLIENT_SIDE - data length is less than %s; len(data)='%d'" % (self._client_detect_length, len(data)))
            return DetectResult(DetectResultType.UNDECIDED)

        index = data.find("".join([self._handshake, self._version_major]))
        if index != -1:
            log(None, CORE_DEBUG, 6, "CLIENT_SIDE - index; index='%d'", index)
            index += 2

            log(None, CORE_DEBUG, 6, "CLIENT_SIDE - Handshake+version_major bytes found;")

            version_minor = data[index]
            if version_minor not in self._version_minor:
                log(None, CORE_DEBUG, 6, "CLIENT_SIDE - version_minor not found")
                return DetectResult(DetectResultType.NOMATCH)
            index += 1

            record_length = struct.unpack("!i", chr(0) + chr(0) + data[index:index+2])[0]
            index += 2

            if data[index] != self._client_hello_type:
                log(None, CORE_DEBUG, 6, "CLIENT_SIDE - hello_type not found at %d: %x" % (index, ord(data[index])))
                return DetectResult(DetectResultType.NOMATCH)
            index += 1

            handshake_length = data[index:index+3]
            index += 3

            if data[index] != self._version_major:
                log(None, CORE_DEBUG, 6, "CLIENT_SIDE - version_major not found")
                return DetectResult(DetectResultType.NOMATCH)
            index += 1

            if data[index] not in self._version_minor:
                log(None, CORE_DEBUG, 6, "CLIENT_SIDE - version_minor not found")
                return DetectResult(DetectResultType.NOMATCH)

            log(None, CORE_DEBUG, 6, "CLIENT_SIDE - Client Hello found. Requesting connection to the server")
            #Found Client Hello, request connection to the server
            self._client_hello_sent = True
            # record_length + handshake(1 byte) + version_major(1 byte) + version_minor(1 byte) + record_length(2 bytes)
            return DetectResult(DetectResultType.COPY_CLIENT, record_length + 5)

        return DetectResult(DetectResultType.NOMATCH)

    def _detect_server(self, data):
        """<method internal="yes"/>"""
        _certificate_list = []
        if len(data) < self._server_detect_length:
            log(None, CORE_DEBUG, 6, "SERVER_SIDE - data length is less than %s; len(data)='%d'", self._server_detect_length, len(data))
            return DetectResult(DetectResultType.UNDECIDED)

        index = 0
        handshake_found = False
        fragments = None
        index = data.find("".join([self._handshake, self._version_major]), index, len(data))
        fragment_begin = index
        while (index != -1):
            index += 2
            log(None, CORE_DEBUG, 6, "SERVER_SIDE - Handshake+version_major bytes found;")
            version_minor = data[index]
            if version_minor not in self._version_minor:
                log(None, CORE_DEBUG, 6, "SERVER_SIDE - version_minor not found")
                index = data.find("".join([self._handshake, self._version_major]), index+1, len(data))
                continue
            index += 1
            record_length = struct.unpack("!i", chr(0) + chr(0) + data[index:index+2])[0]
            index += 2
            if (not fragments) and (len(data) < record_length + index):
                log(None, CORE_DEBUG, 6, "SERVER_SIDE - data length is less than fragment length; len(data)='%d', fragment_lenth='%d'" % (len(data), record_length))
                return DetectResult(DetectResultType.UNDECIDED)
            if (not fragments):
                fragments = data[fragment_begin:fragment_begin+(index-fragment_begin)+record_length]
            else:
                fragments += data[index:index+record_length]

            index += record_length
            index = data.find("".join([self._handshake, self._version_major]), index, len(data))

        index = 5
        if fragments[index] != self._server_hello_type:
            log(None, CORE_DEBUG, 6, "SERVER_SIDE - Server Hello not found")
            return DetectResult(DetectResultType.NOMATCH)
        index += 1
        length = struct.unpack("!i", chr(0) + fragments[index:index+3])[0]
        index += 3
        index += length

        # When the server reply contains a Server Hello message followed by a Change Cipher Spec message -- which is
        # the case if protocol version is 1.3 or version < 1.3 and session reuse is happened -- than the Change Cipher
        # Spec is not copied into fragments variable as it is not handshake message, therefore the length of fragments
        # is less than index which causes IndexError.
        if index >= len(fragments) or fragments[index] != self._handshake_type:
            log(None, CORE_DEBUG, 6, "SERVER_SIDE - Certificate not found")
            return DetectResult(DetectResultType.NOMATCH)
        index += 1

        handshake_found = True

        if handshake_found:
            index += 3 #handshake_length

            certificates_length = struct.unpack("!i", chr(0) + fragments[index:index+3])[0]
            index += 3

            if len(fragments) < certificates_length + self._server_detect_length:
                log(None, CORE_DEBUG, 6, "SERVER_SIDE - data length is less than certificate_length; certificates_length='%d', len(data)='%d'" % (certificates_length, len(fragments)))
                return DetectResult(DetectResultType.UNDECIDED)

            while index < certificates_length:
                #certificate_length = data[index:index+3]
                certificate_length = struct.unpack("!i", chr(0) + fragments[index:index+3])[0]
                index += 3

                certificate_asn1 = fragments[index:index+certificate_length]
                index += certificate_length

                cert = load_certificate(FILETYPE_ASN1, certificate_asn1)
                certificate_pem = dump_certificate(FILETYPE_PEM, cert)

                log(None, CORE_DEBUG, 6, "SERVER_SIDE - Certificate found; commonName='%s'" % str(cert.get_subject()))

                _certificate_list.append(certificate_pem)

            for cert in _certificate_list:
                if cert.strip() == self._cert.strip():
                    log(None, CORE_DEBUG, 6, "SERVER_SIDE - Certificate match!")
                    return DetectResult(DetectResultType.MATCH)

            log(None, CORE_DEBUG, 6, "SERVER_SIDE - Certificate did not match!")
            return DetectResult(DetectResultType.NOMATCH)


class TlsContentType(enum.IntEnum):
    """<class internal="yes"/>"""
    HANDSHAKE = 0x16


class TlsHandshakeType(enum.IntEnum):
    """<class internal="yes"/>"""
    CLIENT_HELLO = 0x01
    SERVER_HELLO = 0x02


class TlsVersion(enum.IntEnum):
    """<class internal="yes"/>"""
    TLS1_0 = 0x0301
    TLS1_1 = 0x0302
    TLS1_2 = 0x0303
    TLS1_3 = 0x0304


class TlsExtensionType(enum.IntEnum):
    """<class internal="yes"/>"""
    SERVER_NAME = 0x00


class TlsExtensionServerNameType(enum.IntEnum):
    """<class internal="yes"/>"""
    SERVER_NAME = 0x00


class TlsDetector(AbstractDetector):
    """<class internal="yes" abstract="no">
      <summary>
        Class for TLS detection.
      </summary>
    </class>
    """

    _TLS_VERSION_SIZE = 2

    _TLS_RECORD_LEN = 5
    _TLS_RECORD_CONTENT_TYPE_SIZE = 1
    _TLS_RECORD_LENGTH_SIZE = 2

    _TLS_HANDSHAKE_TYPE_SIZE = 1
    _TLS_HANDSHAKE_LENGTH_SIZE = 3
    _TLS_HANDSHAKE_HELLO_SESSION_ID_LENGTH_SIZE = 1
    _TLS_HANDSHAKE_HELLO_RANDOM_SIZE = 32
    _TLS_HANDSHAKE_EXTENSIONS_LENGTH_SIZE = 2

    _TLS_HANDSHAKE_CLIENT_HELLO_CIPHER_SUITES_LENGTH_SIZE = 2
    _TLS_HANDSHAKE_CLIENT_HELLO_COMPRSESSION_METHODS_LENGTH_SIZE = 1

    _TLS_EXTENSION_TYPE_SIZE = 2
    _TLS_EXTENSION_LENGTH_SIZE = 2

    _TLS_EXTENSION_SERVER_NAME_LIST_LENGTH_SIZE = 2
    _TLS_EXTENSION_SERVER_NAME_TYPE_SIZE = 1
    _TLS_EXTENSION_SERVER_NAME_LENGTH_SIZE = 2

    @staticmethod
    def _raise_if_not_enough_data(data, offset, size, exception=ValueError):
        if len(data) < size + offset:
            raise exception({'error':'not enough data', 'expected_bytes': size + offset, 'available_bytes': len(data)})

    @staticmethod
    def _parse_numeric(data, offset, size, exception=ValueError):
        prefix = b''

        if size == 1:
            fmt = '!B'
        elif size == 2:
            fmt = '!H'
        elif size == 3:
            fmt = '!I'
            prefix = b'\x00'
        else:
            raise NotImplementedError()  # pragma: no cover

        TlsDetector._raise_if_not_enough_data(data, offset, size, exception)

        return struct.unpack(fmt, prefix + data[offset:offset + size])[0], offset + size

    @staticmethod
    def _parse_tls_version(data, offset):
        tls_version, offset = TlsDetector._parse_numeric(data, offset, TlsDetector._TLS_VERSION_SIZE)
        if tls_version not in list(TlsVersion):
            raise ValueError({'error': 'TLS version cannot be parsed', 'value': tls_version})

        return tls_version, offset

    def _parse_tls_record(self, data):
        offset = 0

        tls_content_type, offset = self._parse_numeric(data, offset, self._TLS_RECORD_CONTENT_TYPE_SIZE, IndexError)
        if tls_content_type != TlsContentType.HANDSHAKE:
            raise ValueError({'error': 'TLS content type is not HANDSHAKE', 'value': tls_content_type})

        _, offset = self._parse_tls_version(data, offset)

        record_length, offset = self._parse_numeric(data, offset, self._TLS_RECORD_LENGTH_SIZE, IndexError)
        self._raise_if_not_enough_data(data, offset, record_length, IndexError)

        return data[offset:offset + record_length]

    def _parse_tls_handshake_header(self, data, offset, handshake_type):
        tls_handshake_type, offset = self._parse_numeric(data, offset, self._TLS_HANDSHAKE_TYPE_SIZE)
        if tls_handshake_type != handshake_type:
            raise ValueError({
                'error': 'TLS handshake type is not {}'.format(handshake_type.name),
                'value': tls_handshake_type,
            })

        message_length, offset = self._parse_numeric(data, offset, self._TLS_HANDSHAKE_LENGTH_SIZE)
        self._raise_if_not_enough_data(data, offset, message_length)

        return offset

    def _parse_tls_handshake_hello_header(self, data, offset):
        _, offset = self._parse_tls_version(data, offset)
        offset += self._TLS_HANDSHAKE_HELLO_RANDOM_SIZE

        session_id_length, offset = self._parse_numeric(data, offset, self._TLS_HANDSHAKE_HELLO_SESSION_ID_LENGTH_SIZE)
        self._raise_if_not_enough_data(data, offset, session_id_length)

        return offset + session_id_length

    def _parse_tls_handshake_client_hello(self, data, offset):
        cipher_suites_length, offset = self._parse_numeric(
            data, offset,
            self._TLS_HANDSHAKE_CLIENT_HELLO_CIPHER_SUITES_LENGTH_SIZE
        )
        self._raise_if_not_enough_data(data, offset, cipher_suites_length)
        offset += cipher_suites_length

        compression_methods_length, offset = self._parse_numeric(
            data, offset,
            self._TLS_HANDSHAKE_CLIENT_HELLO_COMPRSESSION_METHODS_LENGTH_SIZE
        )
        self._raise_if_not_enough_data(data, offset, compression_methods_length)
        offset += compression_methods_length

        return offset

    def _parse_tls_handshake_extension(self, data, offset):
        extension_type, offset = self._parse_numeric(data, offset, self._TLS_EXTENSION_TYPE_SIZE)

        extension_length, offset = self._parse_numeric(
            data, offset,
            self._TLS_EXTENSION_LENGTH_SIZE
        )
        self._raise_if_not_enough_data(data, offset, extension_length)

        extension_data = data[offset:offset + extension_length]
        offset += extension_length

        return extension_type, extension_data, offset

    def _parse_tls_handshake_extensions(self, data, offset):
        extensions_length, offset = self._parse_numeric(
            data, offset,
            self._TLS_HANDSHAKE_EXTENSIONS_LENGTH_SIZE
        )
        self._raise_if_not_enough_data(data, offset, extensions_length)

        extensions = {}
        while offset < len(data):
            extension_type, extension_data, offset = self._parse_tls_handshake_extension(data, offset)
            extensions[extension_type] = extension_data

        return extensions, offset

    @staticmethod
    def _log_exception(message, e):
        description = ', '.join(["{}='{}'".format(key, value) for key, value in e.args[0].iteritems()])
        log(None, CORE_DEBUG, 6, "{}; {}".format(message, description))


class SniDetector(TlsDetector):
    """
    <class maturity="stable">
      <summary>
        Class encapsulating a Detector that determines whether a client
        targets a specific host in a SSL/TLS-encrypted connection.
      </summary>
      <description>
        <para>
          Class encapsulating a Detector that determines whether a client
          targets a specific host in a SSL/TLS-encrypted connection and
          rejects any other protocols and hostnames.
        </para>
        <example>
          <title>SNIDetector example</title>
          <para>The following example defines a DetectorPolicy that detects
          if the traffic is SSL/TLS-encrypted, and uses targets the host
          www.example.com.</para>
          <synopsis>
          DetectorPolicy(name="MySniDetector", detector=SniDetector(RegexpMatcher(match_list=("www.example.com",))))
          </synopsis>
        </example>
      </description>
      <metainfo>
        <attributes>
          <attribute maturity="stable">
            <name>server_name_matcher</name>
            <type>
              <class filter="matcherpolicy" existing="yes"/>
            </type>
            <description>Matcher class (e.g.: RegexpMatcher) used to
            check and filter hostnames in Server Name Indication TLS
            extension, for example,
            <parameter>DetectorPolicy(name="MySniDetector", detector=SniDetector(RegexpMatcher(match_list=("www.example.com",))))</parameter>
            </description>
          </attribute>
       </attributes>
      </metainfo>
    </class>
    """

    def __init__(self, server_name_matcher):
        """
        <method maturity="stable">
          <summary>
            Constructor to initialize a SNIDetector instance.
          </summary>
          <description>
            <para>
              This constructor initializes a SNIDetector instance
            </para>
          </description>
          <metainfo>
            <arguments>
              <argument maturity="stable">
                <name>server_name_matcher</name>
                <type>
                  <class filter="matcherpolicy" existing="yes"/>
                </type>
                <description>Matcher class (e.g.: RegexpMatcher) used to
                check and filter hostnames in Server Name Indication TLS
                extension.
                </description>
              </argument>
            </arguments>
          </metainfo>
        </method>
        """
        super(SniDetector, self).__init__()

        self.server_name_matcher = getMatcher(server_name_matcher)

    def _parse_tls_handshake_extension_server_name(self, data):
        offset = 0

        server_name_list_length, offset = self._parse_numeric(
            data, offset,
            self._TLS_EXTENSION_SERVER_NAME_LIST_LENGTH_SIZE
        )
        self._raise_if_not_enough_data(data, offset, server_name_list_length)

        while offset < len(data):
            hostname_type, offset = self._parse_numeric(data, offset, self._TLS_EXTENSION_SERVER_NAME_TYPE_SIZE)
            hostname_length, offset = self._parse_numeric(data, offset, self._TLS_EXTENSION_SERVER_NAME_LENGTH_SIZE)
            hostname = data[offset:offset + hostname_length]
            offset += hostname_length
            if hostname_type == TlsExtensionServerNameType.SERVER_NAME:
                return hostname.decode('idna')

        raise NotImplementedError({'error': 'unknown server name type'})  # pragma: no cover

    def detect(self, side, data):
        """<method internal="yes"/>"""
        if side != ZEndpoint.EP_CLIENT:
            return DetectResult(DetectResultType.NOMATCH)
        if not self.server_name_matcher:
            return DetectResult(DetectResultType.NOMATCH)

        try:
            data = self._parse_tls_record(data)
            offset = self._parse_tls_handshake_header(data, 0, TlsHandshakeType.CLIENT_HELLO)
            offset = self._parse_tls_handshake_hello_header(data, offset)
            offset = self._parse_tls_handshake_client_hello(data, offset)
            extensions, offset = self._parse_tls_handshake_extensions(data, offset)
        except IndexError as e:
            self._log_exception("Not enough data for parsing TLS client hello message", e)
            return DetectResult(DetectResultType.UNDECIDED)
        except ValueError as e:
            self._log_exception("TLS client hello message cannot be parsed", e)
            return DetectResult(DetectResultType.NOMATCH)

        if TlsExtensionType.SERVER_NAME not in extensions:
            log(None, TLS_ACCOUNTING, 4, "Client initiated connection without Server Name Indication (SNI);")
            return DetectResult(DetectResultType.NOMATCH)

        try:
            server_name = self._parse_tls_handshake_extension_server_name(extensions[TlsExtensionType.SERVER_NAME])
            log(None, TLS_ACCOUNTING, 4, "Client initiated connection with Server Name Indication (SNI); value='{}'".format(server_name))
        except NotImplementedError:  # pragma: no cover
            self._log_exception("TLS client hello message cannot be parsed", e)
            return DetectResult(DetectResultType.NOMATCH)

        try:
            if not self.server_name_matcher.checkMatch(server_name):
                return DetectResult(DetectResultType.NOMATCH)
        except MatcherException:
            return DetectResult(DetectResultType.NOMATCH)

        return DetectResult(DetectResultType.MATCH)


class SshDetector(AbstractDetector):
    """
    <class maturity="stable">
      <summary>
        Class encapsulating a Detector that determines if the traffic uses
        the SSHv2 protocol
      </summary>
      <description>
        <para>
          This Detector determines if the traffic uses the SSHv2 protocol,
          and rejects any other protocol.
        </para>
        <example>
          <title>SshDetector example</title>
          <para>The following example defines a DetectorPolicy that detects
          SSH traffic.</para>
          <synopsis>DetectorPolicy(name="ssh", detector=SshDetector()</synopsis>
        </example>
      </description>
      <metainfo>
        <attributes/>
      </metainfo>
    </class>
    """

    _SSH_VERSION_EXCHANGE_REGEX = re.compile(r"SSH-2.0-[\x21-\x2C\x2E-\x7E]+( [\x20-\x7E]*)?\r\n")
    _SSH_VERSION_EXCHANGE_COMPATIBILITY_REGEX = re.compile(r"SSH-1.99-[\x21-\x2C\x2E-\x7E]+( [\x20-\x7E]*)?\r?\n")

    def __init__(self):
        """<method internal="yes"/>"""
        super(SshDetector, self).__init__()
        self.server_side_protocol = True

    def detect(self, side, data):
        """<method internal="yes"/>"""

        if (len(data) <= 255 and (self._SSH_VERSION_EXCHANGE_REGEX.match(data) or
                self._SSH_VERSION_EXCHANGE_COMPATIBILITY_REGEX.match(data))):

            log(None, CORE_DEBUG, 6, "SSH protocol found;")
            return DetectResult(DetectResultType.MATCH)

        return DetectResult(DetectResultType.NOMATCH)
