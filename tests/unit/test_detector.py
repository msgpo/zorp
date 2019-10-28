#!/usr/bin/env python2.7

import unittest

from Zorp.Common import LoggerSingleton
from Zorp.Exceptions import MatcherException
from Zorp.Matcher import AbstractMatcher, RegexpMatcher

from Zorp.Zorp import ZEndpoint
from Zorp.Detector import DetectResult, DetectResultType, AbstractDetector, HttpDetector, SshDetector, SniDetector


class TestAbstractDetector(unittest.TestCase):
    def test_abstract(self):
        with self.assertRaises(NotImplementedError):
            AbstractDetector().detect(ZEndpoint.EP_CLIENT, b'')


class TestHttpDetector(unittest.TestCase):
    def setUp(self):
        LoggerSingleton().init('TestHttpDetector', use_syslog=False)
        self.detector = HttpDetector()

    def test_nomatch(self):
        self.assertEqual(self.detector.detect(ZEndpoint.EP_SERVER, b'GET / HTTP/1.1').result, DetectResultType.NOMATCH)

    def test_undecided(self):
        self.assertEqual(self.detector.detect(ZEndpoint.EP_CLIENT, b'').result, DetectResultType.NOMATCH)
        self.assertEqual(self.detector.detect(ZEndpoint.EP_CLIENT, b'GET / ').result, DetectResultType.NOMATCH)

    def test_match(self):
        self.assertEqual(self.detector.detect(ZEndpoint.EP_CLIENT, b'GET / HTTP/1.1').result, DetectResultType.MATCH)
        self.assertEqual(self.detector.detect(ZEndpoint.EP_CLIENT, b'POST / HTTP/1.1').result, DetectResultType.MATCH)

        self.assertEqual(self.detector.detect(ZEndpoint.EP_CLIENT, b'GET / HTTP/1.0').result, DetectResultType.MATCH)


class TestSshDetector(unittest.TestCase):
    def setUp(self):
        LoggerSingleton().init('TestSshDetector', use_syslog=False)
        self.detector = SshDetector()

    def test_nomatch(self):
        """Testing SSH identification strings where SSH detection must fail."""

        test_cases = [
            {
                "input": b'',
                "description": "Empty identification string"
            },
            {
                "input": b'SSH-1.8-software_ver1.0\r\n',
                "description": "Unsupported protocol version"
            },
            {
                "input": b'SSH-2.0-software ' + b'A' * 237 + b'\r\n',
                "description": "Max length (255 bytes) exceeded"
            },
            {
                "input": b'SSH-2.0\r\n',
                "description": "No software version given"
            },
            {
                "input": b'SSH-2.0 software\r\n',
                "description": "Missing hyphen before software version"
            },
            {
                "input": b'SSH-2.0-software_ver1.0.0-comment\r\n',
                "description": "Missing space before comment OR hyphen in sw version string"
            },
            {
                "input": b'SSH-2.0-software\x09ver1.0\r\n',
                "description": "Illegal character (a tab) in sw version"
            },
            {
                "input": b'SSH-2.0-software_ver1.0\n',
                "description": "Illegal identification string termination"
            }
        ]

        for case in test_cases:
            self.assertEqual(
                self.detector.detect(
                    ZEndpoint.EP_SERVER,
                    case["input"]
                ).result,
                DetectResultType.NOMATCH,
                msg=case["description"]
            )

    def test_match(self):
        """Testing SSH identification strings where SSH must be detected."""

        test_cases = [
            {
                "input": b'SSH-2.0-software_ver1.0.0\r\n',
                "description": "Standard identification string"
            },
            {
                "input": b'SSH-1.99-software_ver_1.0.0\r\n',
                "description": "Standard identification string, older protocol version"
            },
            {
                "input": b'SSH-2.0-software_ver1.0.0 comment1=a;comment2=b\r\n',
                "description": "Identification string with comments"
            },
            {
                "input": b'SSH-2.0-software_ver1.0.0 comment1=a comment2=b\r\n',
                "description": "Identification string with comments, separated by space"
            },
            {
                "input": b'SSH-2.0-softwareversion \r\n',
                "description": "Space allowed without comments after software version"
            },
            {
                "input": b'SSH-2.0-software ' + b'A' * 236 + b'\r\n',
                "description": "Max length (255 bytes) boundary positive verification"
            },
            {
                "input": b'SSH-1.99-software comment\n',
                "description": "ID string with older protocol version and single newline termination"
            }
        ]

        for case in test_cases:
            self.assertEqual(
                self.detector.detect(
                    ZEndpoint.EP_SERVER,
                    case["input"]
                ).result,
                DetectResultType.MATCH,
                msg=case["description"]
            )


class TestTlsDetector(unittest.TestCase):
    def setUp(self):
        LoggerSingleton().init('TestSniDetector', use_syslog=False)
        self.detector = SniDetector(RegexpMatcher(match_list=(".*",), ignore_list=None))

    def test_tls_record(self):
        self.assertEqual(
            self.detector.detect(ZEndpoint.EP_CLIENT, b'').result,
            DetectResultType.UNDECIDED
        )
        self.assertEqual(
            self.detector.detect(ZEndpoint.EP_CLIENT, b'\x00').result,
            DetectResultType.NOMATCH
        )

        self.assertEqual(
            self.detector.detect(ZEndpoint.EP_CLIENT, b'\x16\x03\x01\x00\x00').result,
            DetectResultType.NOMATCH
        )
        self.assertEqual(
            self.detector.detect(ZEndpoint.EP_CLIENT, b'\x16\x03\x01\x00\x01').result,
            DetectResultType.UNDECIDED
        )

    def test_tls_record_version(self):
        self.assertEqual(
            self.detector.detect(ZEndpoint.EP_CLIENT, b'\x16\x03\x01\x00\x00').result,
            DetectResultType.NOMATCH
        )
        self.assertEqual(
            self.detector.detect(ZEndpoint.EP_CLIENT, b'\x16\x03\x05\x00\x00').result,
            DetectResultType.NOMATCH
        )

    def test_tls_handshake_header(self):
        self.assertEqual(
            self.detector.detect(
                ZEndpoint.EP_CLIENT,
                b'\x16\x03\x01\x00\x01' +
                b'\xff'  # invalid handshake type
            ).result,
            DetectResultType.NOMATCH
        )

        self.assertEqual(
            self.detector.detect(
                ZEndpoint.EP_CLIENT,
                b'\x16\x03\x01\x00\x01' +
                b'\x01'  # invalid handshake type
            ).result,
            DetectResultType.NOMATCH
        )
        self.assertEqual(
            self.detector.detect(
                ZEndpoint.EP_CLIENT,
                b'\x16\x03\x01\x00\x06' +
                b'\x01\x00\x00\x02\x03\x05'  # invalid tls version
            ).result,
            DetectResultType.NOMATCH
        )

    def test_tls_handshake_client_hello(self):
        self.assertEqual(
            self.detector.detect(
                ZEndpoint.EP_CLIENT,
                b'\x16\x03\x01\x00\x2f' +
                b'\x01\x00\x00\x0b\x03\x01' +
                b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' +  # random
                b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' +
                b'\x00' +  # session id length
                b'\x00\x04' +  # cipher suites length
                b'\x01\x02\x03\x04' +  # cipher suites
                b'\x01' +  # compression methods length
                b'\x00' +  # compression methods
                b''
            ).result,
            DetectResultType.NOMATCH
        )


class TestMatcerAlwaysRaisesMatcherException(AbstractMatcher):
    def checkMatch(self, str):
        raise MatcherException('')


class TestSniDetector(unittest.TestCase):
    def setUp(self):
        LoggerSingleton().init('TestSniDetector', use_syslog=False)

        self.detector = SniDetector(RegexpMatcher(match_list=("www.example.com",), ignore_list=None))

        self.tls_client_hello_with_matching_sni = (
            b'\x16\x03\x01\x00\x52' +
            b'\x01\x00\x00\x4d\x03\x01' +
            b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' +  # random
            b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' +
            b'\x00' +  # session id length
            b'\x00\x04' +  # cipher suites length
            b'\x01\x02\x03\x04' +  # cipher suites
            b'\x01' +  # compression methods length
            b'\x00' +  # compression methods
            b'\x00\x21' +  # extensions length
            b'\xfa\xfa\x00\x01\x00' +  # extension grease
            b'\x00\x00\x00\x14\x00\x12\x00\x00\x0f'  # extension server name
            b'www.example.com' +
            b'\xaa\xaa\x00\x00' +  # extension grease
            b''
        )

    def test_tls_handshake_extensions(self):
        self.assertEqual(
            self.detector.detect(
                ZEndpoint.EP_CLIENT,
                self.tls_client_hello_with_matching_sni
            ).result,
            DetectResultType.MATCH
        )

        # no matching hostname
        self.assertEqual(
            self.detector.detect(
                ZEndpoint.EP_CLIENT,
                b'\x16\x03\x01\x00\x52' +
                b'\x01\x00\x00\x4d\x03\x01' +
                b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' +  # random
                b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' +
                b'\x00' +  # session id length
                b'\x00\x04' +  # cipher suites length
                b'\x01\x02\x03\x04' +  # cipher suites
                b'\x01' +  # compression methods length
                b'\x00' +  # compression methods
                b'\x00\x21' +  # extensions length
                b'\xfa\xfa\x00\x01\x00' +  # extension grease
                b'\x00\x00\x00\x14\x00\x12\x00\x00\x0f'  # extension server name
                b'www.-------.com' +
                b'\xaa\xaa\x00\x00' +  # extension grease
                b''
            ).result,
            DetectResultType.NOMATCH
        )

        # no server name extension
        self.assertEqual(
            self.detector.detect(
                ZEndpoint.EP_CLIENT,
                b'\x16' +  # TLS handshake
                b'\x03\x01' +  # TLS version
                b'\x00\x36' +  # record length
                b'\x01' +  # client hello
                b'\x00\x00\x31' +  # handshake length
                b'\x03\x01' +  # TLS version
                b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' +  # random
                b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' +
                b'\x00' +  # session id length
                b'\x00\x04' +  # cipher suites length
                b'\x01\x02\x03\x04' +  # cipher suites
                b'\x01' +  # compression methods length
                b'\x00' +  # compression methods
                b'\x00\x05' +  # extensions length
                b'\xfa\xfa\x00\x01\x00' +  # extension grease
                b''
            ).result,
            DetectResultType.NOMATCH
        )

    def test_definite_no_match(self):
        self.assertEqual(
            self.detector.detect(
                ZEndpoint.EP_SERVER,
                self.tls_client_hello_with_matching_sni).result,
            DetectResultType.NOMATCH
        )

        self.detector.server_name_matcher = None
        self.assertEqual(
            self.detector.detect(
                ZEndpoint.EP_CLIENT,
                self.tls_client_hello_with_matching_sni).result,
            DetectResultType.NOMATCH
        )

        self.detector.server_name_matcher = TestMatcerAlwaysRaisesMatcherException()
        self.assertEqual(
            self.detector.detect(
                ZEndpoint.EP_CLIENT,
                self.tls_client_hello_with_matching_sni).result,
            DetectResultType.NOMATCH
        )


if __name__ == '__main__':
    unittest.main()
