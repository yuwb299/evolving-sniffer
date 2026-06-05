"""
Tests for http_parser module.
"""

import pytest
from http_parser import (
    parse_http_request,
    parse_http_response,
    parse_http_headers,
    is_http_payload
)
from packet_structures import HTTPRequest, HTTPResponse


class TestParseHttpHeaders:
    """Tests for parse_http_headers helper."""
    
    def test_simple_headers(self):
        lines = ["Host: example.com", "User-Agent: TestAgent"]
        headers = parse_http_headers(lines)
        assert headers == {"Host": "example.com", "User-Agent": "TestAgent"}
    
    def test_headers_with_colon_in_value(self):
        lines = ["Location: http://example.com:8080/path"]
        headers = parse_http_headers(lines)
        assert headers == {"Location": "http://example.com:8080/path"}
    
    def test_headers_with_spaces(self):
        lines = ["Content-Type:   application/json  "]
        headers = parse_http_headers(lines)
        assert headers == {"Content-Type": "application/json"}


class TestParseHttpRequest:
    """Tests for parse_http_request function."""
    
    def test_simple_get_request(self):
        data = b"GET /index.html HTTP/1.1\r\nHost: localhost\r\n\r\n"
        req = parse_http_request(data)
        assert req is not None
        assert req.method == "GET"
        assert req.path == "/index.html"
        assert req.version == "HTTP/1.1"
        assert req.headers["Host"] == "localhost"
        assert req.body == b''
    
    def test_post_request_with_body(self):
        # Note: Body parsing here just takes bytes after \r\n\r\n
        data = b"POST /submit HTTP/1.1\r\nHost: api.example.com\r\nContent-Length: 4\r\n\r\ntest"
        req = parse_http_request(data)
        assert req is not None
        assert req.method == "POST"
        assert req.path == "/submit"
        assert req.body == b"test"
    
    def test_request_with_multiple_headers(self):
        data = (
            b"GET / HTTP/1.1\r\n"
            b"Host: www.google.com\r\n"
            b"User-Agent: Mozilla/5.0\r\n"
            b"Accept: */*\r\n"
            b"\r\n"
        )
        req = parse_http_request(data)
        assert req is not None
        assert len(req.headers) == 3
        assert req.headers["User-Agent"] == "Mozilla/5.0"
    
    def test_malformed_request_line(self):
        data = b"INVALID REQUEST\r\n\r\n"
        req = parse_http_request(data)
        assert req is None
        
    def test_incomplete_request(self):
        data = b"GET /"
        req = parse_http_request(data)
        assert req is None

    def test_method_put(self):
        data = b"PUT /resource/1 HTTP/1.1\r\nHost: localhost\r\n\r\n"
        req = parse_http_request(data)
        assert req is not None
        assert req.method == "PUT"


class TestParseHttpResponse:
    """Tests for parse_http_response function."""
    
    def test_simple_200_ok(self):
        data = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html></html>"
        resp = parse_http_response(data)
        assert resp is not None
        assert resp.version == "HTTP/1.1"
        assert resp.status_code == 200
        assert resp.status_text == "OK"
        assert resp.headers["Content-Type"] == "text/html"
        assert resp.body == b"<html></html>"
    
    def test_404_not_found(self):
        data = b"HTTP/1.0 404 Not Found\r\nServer: TestServer\r\n\r\n"
        resp = parse_http_response(data)
        assert resp is not None
        assert resp.version == "HTTP/1.0"
        assert resp.status_code == 404
        assert resp.status_text == "Not Found"
    
    def test_500_internal_server_error(self):
        data = b"HTTP/1.1 500 Internal Server Error\r\n\r\n"
        resp = parse_http_response(data)
        assert resp is not None
        assert resp.status_code == 500
    
    def test_malformed_response_line(self):
        data = b"HTTP/1.1 BAD_CODE OK\r\n\r\n"
        resp = parse_http_response(data)
        assert resp is None
    
    def test_response_with_body(self):
        data = b"HTTP/1.1 200 OK\r\n\r\n" + b"\x00\x01\x02\x03"
        resp = parse_http_response(data)
        assert resp is not None
        assert resp.body == b"\x00\x01\x02\x03"


class TestIsHttpPayload:
    """Tests for is_http_payload heuristic."""
    
    def test_get_request(self):
        assert is_http_payload(b"GET / HTTP/1.1\r\n") is True
        
    def test_post_request(self):
        assert is_http_payload(b"POST / HTTP/1.1\r\n") is True
        
    def test_response(self):
        assert is_http_payload(b"HTTP/1.1 200 OK\r\n") is True
        
    def test_ssh(self):
        assert is_http_payload(b"SSH-2.0-OpenSSH") is False
        
    def test_random_bytes(self):
        assert is_http_payload(b"\x12\x34\x56\x78") is False
        
    def test_empty(self):
        assert is_http_payload(b"") is False
