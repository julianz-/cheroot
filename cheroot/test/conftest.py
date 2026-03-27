"""Pytest configuration module.

Contains fixtures, which are tightly bound to the Cheroot framework
itself, useless for end-users' app testing.
"""

import gc
import signal
import socket
import sys
import threading
import time
import traceback

import pytest

from cheroot import connections, server, testing

from .._compat import IS_MACOS, IS_WINDOWS
from ..server import Gateway, HTTPServer
from ..testing import (  # noqa: F401  # pylint: disable=unused-import
    get_server_client,
    native_server,
    thread_and_native_server,
    thread_and_wsgi_server,
    wsgi_server,
)


try:
    import tracemalloc
except ImportError:
    tracemalloc = None

HAS_TRACEMALLOC = tracemalloc is not None


if HAS_TRACEMALLOC:
    tracemalloc.start()

_original_socket = socket.socket

print('🕵️ Socket tracking is ACTIVE for all tests')


DIVIDER_SIDE_WIDTH = 20
DIVIDER_TOTAL_WIDTH = 67


def _dump_threads(signum, frame):
    for thread_id, stack in sys._current_frames().items():
        print(f'\n=== Thread {thread_id} ===')
        traceback.print_stack(stack)


if hasattr(signal, 'SIGUSR1'):
    signal.signal(signal.SIGUSR1, _dump_threads)

_original_unraisablehook = sys.unraisablehook


def _unraisablehook(unraisable):
    if isinstance(unraisable.exc_value, ResourceWarning):
        obj = unraisable.object
        if isinstance(obj, TraceableSocket):
            birth = ''.join(
                getattr(obj, '_birth_certificate', ['(no birth certificate)']),
            )
            print(f'\nSocket birth certificate:\n{birth}', file=sys.stderr)
    _original_unraisablehook(unraisable)


sys.unraisablehook = _unraisablehook


class TraceableSocket(_original_socket):
    """A socket subclass that records its creation traceback for leak detection."""

    def __init__(self, *args, **kwargs):
        """Initialize the TraceableSocket and record its creation traceback."""
        super().__init__(*args, **kwargs)
        self._birth_certificate = ''.join(traceback.format_stack())

    def accept(self):
        """Override accept to track accepted sockets."""
        fd, addr = super().accept()
        fd._birth_certificate = ''.join(traceback.format_stack())
        return fd, addr


@pytest.fixture(autouse=False)
def _check_for_socket_leaks():  # noqa: WPS210
    """Check for socket leaks after each test."""
    yield
    gc.collect()


# Replace the global socket creator with our spy
for module in (server, connections, testing):
    module.socket.socket = TraceableSocket


@pytest.fixture
def http_request_timeout():
    """Return a common HTTP request timeout for tests with queries."""
    computed_timeout = 0.5

    if IS_MACOS:
        computed_timeout *= 2

    if IS_WINDOWS:
        computed_timeout *= 10

    return computed_timeout


@pytest.fixture
# pylint: disable=redefined-outer-name
def wsgi_server_thread(thread_and_wsgi_server):  # noqa: F811
    """Set up and tear down a Cheroot WSGI server instance.

    This exposes the server thread.
    """
    server_thread, _srv = thread_and_wsgi_server
    return server_thread


@pytest.fixture
# pylint: disable=redefined-outer-name
def native_server_thread(thread_and_native_server):  # noqa: F811
    """Set up and tear down a Cheroot HTTP server instance.

    This exposes the server thread.
    """
    server_thread, _srv = thread_and_native_server
    return server_thread


@pytest.fixture
# pylint: disable=redefined-outer-name
def wsgi_server_client(wsgi_server):  # noqa: F811
    """Create a test client out of given WSGI server."""
    client = get_server_client(wsgi_server)

    yield client

    # Close the internal persistent connection to trigger thread exit
    if hasattr(client, '_http_connection'):
        conn = client._http_connection
        if conn and hasattr(conn, 'close'):
            conn.close()


@pytest.fixture
# pylint: disable=redefined-outer-name
def native_server_client(native_server):  # noqa: F811
    """Create a test client out of given HTTP server."""
    return get_server_client(native_server)


@pytest.fixture
def http_server():
    """Provision a server creator as a fixture."""

    def start_srv():
        bind_addr = yield
        if bind_addr is None:
            return
        httpserver = make_http_server(bind_addr)
        yield httpserver
        yield httpserver

    srv_creator = iter(start_srv())
    next(srv_creator)  # pylint: disable=stop-iteration-return
    yield srv_creator
    try:
        while True:
            httpserver = next(srv_creator)
            if httpserver is not None:
                httpserver.stop()
    except StopIteration:
        pass


def make_http_server(bind_addr):
    """Create and start an HTTP server bound to ``bind_addr``."""
    httpserver = HTTPServer(
        bind_addr=bind_addr,
        gateway=Gateway,
    )

    threading.Thread(target=httpserver.safe_start).start()

    while not httpserver.ready:
        time.sleep(0.1)

    return httpserver
