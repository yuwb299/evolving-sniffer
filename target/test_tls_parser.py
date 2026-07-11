"""
Tests for tls_parser module.
"""

import pytest
import struct
from tls_parser import (
    parse_tls_record,
    parse_tls_handshake,
    parse_client_hello,
    parse_extensions
)
from packet_structures import TLSRecord, TLSHandshake


def build_sni_extension(sni: bytes) -> bytes:
    """Build a single SNI extension."""
    # SNI extension type = 0x0000
    # Name type = 0x00 (host_name)
    sni_name = b'\x00' + struct.pack('!H', len(sni)) + sni
    sni_list = struct.pack('!H', len(sni_name)) + sni_name
    # ext_type(2) + ext_len(2) + data
    return struct.pack('!HH', 0x0000, len(sni_list)) + sni_list


def build_extensions_block(extensions: list) -> bytes:
    """Build the extensions block with length prefix."""
    ext_data = b''.join(extensions)
    return struct.pack('!H', len(ext_data)) + ext_data


def build_client_hello_body(version=0x0303, sni=b"example.com", session_id=b'',
                             cipher_suites=b'\x00\x2f', compression=b'\x00'):
    """
    Build a ClientHello body (without the handshake header).
    Returns just the body bytes.
    """
    body = b''
    # Version (2 bytes)
    body += struct.pack('!H', version)
    # Random (32 bytes)
    body += b'\x01' * 32
    # Session ID
    body += struct.pack('!B', len(session_id)) + session_id
    # Cipher Suites
    body += struct.pack('!H', len(cipher_suites)) + cipher_suites
    # Compression Methods
    body += struct.pack('!B', len(compression)) + compression
    # Extensions
    exts = []
    if sni:
        exts.append(build_sni_extension(sni))
    body += build_extensions_block(exts)
    return body


def build_handshake(msg_type: int, body: bytes) -> bytes:
    """Build a handshake message: type(1) + length(3) + body."""
    length = len(body)
    return struct.pack('!B', msg_type) + struct.pack('!I', length)[1:] + body


def build_tls_record(content_type: int, version: int, payload: bytes) -> bytes:
    """Build a TLS record: type(1) + version(2) + length(2) + payload."""
    return struct.pack('!BHH', content_type, version, len(payload)) + payload


class TestParseTlsRecord:
    def test_valid_handshake_record(self):
        payload = b'\x01\x02\x03\x04'
        data = build_tls_record(0x16, 0x0303, payload)
        record = parse_tls_record(data)
        assert record is not None
        assert record.content_type == 0x16
        assert record.version == 0x0303
        assert record.length == 4
        assert record.payload == payload

    def test_too_short(self):
        record = parse_tls_record(b'\x16\x03\x03')
        assert record is None

    def test_truncated_payload(self):
        """Payload claims more bytes than available."""
        data = b'\x16\x03\x03\x00\x20\x01\x02'  # claims 32 bytes, only 2 available
        record = parse_tls_record(data)
        assert record is not None
        assert record.length == 0x20
        assert record.payload == b'\x01\x02'

    def test_content_type_name(self):
        record = TLSRecord(content_type=22, version=0x0303, length=0, payload=b'')
        assert record.get_content_type_name() == "Handshake"

    def test_version_name(self):
        record = TLSRecord(content_type=22, version=0x0303, length=0, payload=b'')
        assert record.get_version_name() == "TLS 1.2"


class TestParseExtensions:
    def test_sni_extraction(self):
        """Test that SNI is correctly extracted from extensions."""
        sni_ext = build_sni_extension(b"google.com")
        ext_block = build_extensions_block([sni_ext])
        sni, remaining = parse_extensions(ext_block)
        assert sni == "google.com"

    def test_sni_example_com(self):
        sni_ext = build_sni_extension(b"example.com")
        ext_block = build_extensions_block([sni_ext])
        sni, _ = parse_extensions(ext_block)
        assert sni == "example.com"

    def test_no_sni_extension(self):
        """Extensions block without SNI."""
        # Build a non-SNI extension (type 0x0010 = ALPN)
        alpn_data = b'\x00\x02\x00\x00'  # fake ALPN data
        ext = struct.pack('!HH', 0x0010, len(alpn_data)) + alpn_data
        ext_block = build_extensions_block([ext])
        sni, _ = parse_extensions(ext_block)
        assert sni is None

    def test_empty_extensions(self):
        sni, _ = parse_extensions(b'\x00\x00')
        assert sni is None

    def test_too_short(self):
        sni, data = parse_extensions(b'\x00')
        assert sni is None


class TestParseClientHello:
    def test_basic_client_hello(self):
        """Test parsing a ClientHello with SNI."""
        body = build_client_hello_body(sni=b"example.com")
        result = parse_client_hello(body)
        assert result is not None
        assert result.sni == "example.com"

    def test_client_hello_with_sni(self):
        body = build_client_hello_body(sni=b"google.com")
        result = parse_client_hello(body)
        assert result is not None
        assert result.sni == "google.com"

    def test_client_hello_no_sni(self):
        """ClientHello without extensions (no SNI)."""
        body = b''
        body += struct.pack('!H', 0x0303)  # version
        body += b'\x00' * 32  # random
        body += b'\x00'  # session id length = 0
        body += struct.pack('!H', 2) + b'\x00\x2f'  # cipher suites
        body += b'\x01\x00'  # compression: 1 method, null
        # No extensions
        result = parse_client_hello(body)
        assert result is not None
        assert result.sni is None

    def test_client_hello_with_session_id(self):
        """ClientHello with a session ID."""
        sid = b'\xaa\xbb\xcc\xdd'
        body = build_client_hello_body(sni=b"test.com", session_id=sid)
        result = parse_client_hello(body)
        assert result is not None
        assert result.sni == "test.com"

    def test_too_short(self):
        result = parse_client_hello(b'\x00' * 10)
        assert result is None


class TestParseTlsHandshake:
    def test_client_hello_via_handshake_parser(self):
        """Test full handshake parsing including SNI."""
        body = build_client_hello_body(sni=b"example.com")
        msg = build_handshake(0x01, body)
        hs = parse_tls_handshake(msg)
        assert hs is not None
        assert hs.handshake_type == TLSHandshake.CLIENT_HELLO
        assert hs.sni == "example.com"

    def test_non_client_hello(self):
        """Test parsing a ServerHello (no SNI parsing)."""
        body = struct.pack('!H', 0x0303) + b'\x00' * 32 + b'\x00'  # version + random + sid_len
        msg = build_handshake(0x02, body)
        hs = parse_tls_handshake(msg)
        assert hs is not None
        assert hs.handshake_type == TLSHandshake.SERVER_HELLO
        assert hs.sni is None

    def test_too_short(self):
        hs = parse_tls_handshake(b'\x01\x00')
        assert hs is None


class TestFullStack:
    """Test full TLS record -> handshake -> SNI extraction."""

    def test_full_client_hello_over_wire(self):
        """Build a complete TLS ClientHello wrapped in a record."""
        body = build_client_hello_body(sni=b"www.example.org")
        handshake = build_handshake(0x01, body)
        record_data = build_tls_record(0x16, 0x0301, handshake)

        # Parse record
        record = parse_tls_record(record_data)
        assert record is not None
        assert record.content_type == TLSRecord.HANDSHAKE

        # Parse handshake from record payload
        hs = parse_tls_handshake(record.payload)
        assert hs is not None
        assert hs.handshake_type == TLSHandshake.CLIENT_HELLO
        assert hs.sni == "www.example.org"