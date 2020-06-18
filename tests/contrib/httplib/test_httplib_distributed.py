# Standard library
import contextlib
import sys

# Project
from ddtrace import config
from ddtrace.compat import httplib
from ddtrace.pin import Pin
from ddtrace.vendor import wrapt

from ...base import BaseTracerTestCase
from .test_httplib import SOCKET, HTTPLibBaseMixin


class TestHTTPLibDistributed(HTTPLibBaseMixin, BaseTracerTestCase):
    def setUp(self):
        super(TestHTTPLibDistributed, self).setUp()
        self.httplib_request = b''

    def send(self, func, instance, args, kwargs):
        self.httplib_request += args[0]
        return func(*args, **kwargs)

    def headers_here(self, tracer, root_span):
        # headers = request.headers
        assert b'x-datadog-trace-id' in self.httplib_request
        assert b'x-datadog-parent-id' in self.httplib_request
        assert str(root_span.trace_id).encode('utf-8') in self.httplib_request
        return True

    def headers_not_here(self, tracer):
        assert b'x-datadog-trace-id' not in self.httplib_request
        assert b'x-datadog-parent-id' not in self.httplib_request
        return True

    def get_http_connection(self, *args, **kwargs):
        conn = httplib.HTTPConnection(*args, **kwargs)
        Pin.override(conn, tracer=self.tracer)
        return conn

    def test_propagation(self):
        conn = self.get_http_connection(SOCKET)
        with contextlib.closing(conn):
            conn.send = wrapt.FunctionWrapper(conn.send, self.send)
            conn.request('POST', '/status/200', body='key=value')
            resp = conn.getresponse()

        spans = self.tracer.writer.pop()
        self.assertEqual(len(spans), 1)
        span = spans[0]
        assert self.headers_here(self.tracer, span)

    def test_propagation_disabled(self):
        with self.override_config('httplib', dict(distributed_tracing=False)):
            conn = self.get_http_connection(SOCKET)
            with contextlib.closing(conn):
                conn.send = wrapt.FunctionWrapper(conn.send, self.send)
                conn.request('POST', '/status/200', body='key=value')
                resp = conn.getresponse()

        spans = self.tracer.writer.pop()
        self.assertEqual(len(spans), 1)
        span = spans[0]
        assert self.headers_not_here(self.tracer)
