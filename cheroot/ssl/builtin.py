"""
A library for integrating Python's builtin :py:mod:`ssl` library with Cheroot.

The :py:mod:`ssl` module must be importable for SSL functionality.

To use this module, set ``HTTPServer.ssl_adapter`` to an instance of
``BuiltinSSLAdapter``.
"""

import socket
import sys
import threading
from contextlib import suppress


try:
    import ssl
except ImportError:
    ssl = None

try:
    from _pyio import DEFAULT_BUFFER_SIZE
except ImportError:
    try:
        from io import DEFAULT_BUFFER_SIZE
    except ImportError:
        DEFAULT_BUFFER_SIZE = -1

from .. import errors
from ..makefile import StreamReader, StreamWriter
from ..server import HTTPServer
from . import Adapter


def _assert_ssl_exc_contains(exc, *msgs):
    """Check whether SSL exception contains either of messages provided."""
    if len(msgs) < 1:
        raise TypeError(
            '_assert_ssl_exc_contains() requires '
            'at least one message to be passed.',
        )
    err_msg_lower = str(exc).lower()
    return any(m.lower() in err_msg_lower for m in msgs)


def _loopback_for_cert_thread(context, server, handshake_done):
    """Thread target for loopback connection to parse a cert."""
    # As we only care about parsing the certificate, the failure of
    # which will cause an exception in ``_loopback_for_cert``,
    # we can safely ignore connection and ssl related exceptions. Ref:
    # https://github.com/cherrypy/cheroot/issues/302#issuecomment-662592030
    ssl_sock = None
    handshake_timeout = 5.0  # Prevent CI from hanging on handshake
    try:
        with suppress(Exception):
            ssl_sock = context.wrap_socket(
                server,
                do_handshake_on_connect=True,
                server_side=True,
            )
            if ssl_sock:
                with suppress(OSError):
                    # TLS 1.3 sends session tickets as a post-handshake message
                    # at an unspecified time. On Windows, closing before the
                    # client receives them is treated as an incomplete
                    # handshake, raising ConnectionAbortedError. We send a
                    # small amount of data to give the server a chance to send
                    # the tickets and close cleanly. This is a race condition
                    # so the error may still occasionally occur
                    ssl_sock.send(b'0000')
    finally:
        if ssl_sock:
            with suppress(OSError):
                ssl_sock.close()

        # Wait for main thread to finish its wrap attempt
        # before we kill the raw server socket.
        handshake_done.wait(timeout=handshake_timeout)
        server.close()


def _get_cert_from_ssl_sock(ssl_sock):
    """Receive cert data from ssl socket and return parsed cert."""
    ssl_sock.recv(4)
    return ssl_sock.getpeercert()


def _loopback_for_cert(
    certificate,
    private_key,
    certificate_chain,
    *,
    private_key_password=None,
):
    """Create a loopback connection to parse a cert.

    Used by the builtin adapter to retrieve information about the
    server's SSL certificate that will be available in the
    WSGI environment variables. Since Python's ssl module has no
    public API to parse a cert directly, this function performs a
    minimal SSL handshake with itself to extract the cert details.
    """
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)

    # add the CA file if it's provided
    if certificate_chain:
        context.load_verify_locations(cafile=certificate_chain)

    context.load_cert_chain(
        certificate,
        private_key,
        password=private_key_password,
    )
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    socket_timeout = 2.0
    # Ensure thread has time to finish after handshake timeout
    thread_timeout = socket_timeout + 1.0
    client, server = socket.socketpair()
    client.settimeout(socket_timeout)  # Prevent CI from hanging on handshake
    server.settimeout(socket_timeout)

    handshake_done = threading.Event()

    # `wrap_socket` will block until the ssl handshake is complete.
    # Both ends must call wrap_socket concurrently —
    # hence we create a thread to call on the server side.
    # handshake_done signals to the server thread that the main thread
    # has finished, so the thread can exit cleanly regardless of
    # success or failure.
    thread = threading.Thread(
        target=_loopback_for_cert_thread,
        args=(context, server, handshake_done),
    )

    thread.start()

    ssl_sock = None

    try:
        try:
            ssl_sock = context.wrap_socket(
                client,
                do_handshake_on_connect=True,
                server_side=False,
            )
            return _get_cert_from_ssl_sock(ssl_sock)
        finally:
            if ssl_sock:
                with suppress(OSError):
                    ssl_sock.close()
    finally:
        # Signal the thread that the main thread is exiting its wrap attempt
        handshake_done.set()

        # Wait for thread to finish BEFORE closing ANY raw sockets
        thread.join(timeout=thread_timeout)

        # Final cleanup of transport layer
        # Doesn't matter if the sockets have already been closed
        client.close()
        server.close()


def _parse_cert(
    certificate,
    private_key,
    certificate_chain,
    *,
    private_key_password=None,
):
    """Parse a certificate."""
    # loopback_for_cert uses socket.socketpair which was only
    # introduced in Python 3.0 for *nix and 3.5 for Windows
    # and requires OS support (AttributeError, OSError)
    # it also requires a private key either in its own file
    # or combined with the cert (SSLError)
    with suppress(AttributeError, ssl.SSLError, OSError):
        return _loopback_for_cert(
            certificate,
            private_key,
            certificate_chain,
            private_key_password=private_key_password,
        )

    # KLUDGE: using an undocumented, private, test method to parse a cert
    # unfortunately, it is the only built-in way without a connection
    # as a private, undocumented method, it may change at any time
    # so be tolerant of *any* possible errors it may raise
    with suppress(Exception):
        return ssl._ssl._test_decode_cert(certificate)

    return {}


def _sni_callback(sock, sni, context):
    """Handle the SNI callback to tag the socket with the SNI."""
    sock.sni = sni
    # return None to allow the TLS negotiation to continue


class BuiltinSSLAdapter(Adapter):
    """Wrapper for integrating Python's builtin :py:mod:`ssl` with Cheroot."""

    certificate = None
    """The file name of the server SSL certificate."""

    private_key = None
    """The file name of the server's private key file."""

    certificate_chain = None
    """The file name of the certificate chain file."""

    ciphers = None
    """The ciphers list of SSL."""

    private_key_password = None
    """Optional passphrase for password protected private key."""

    # from mod_ssl/pkg.sslmod/ssl_engine_vars.c ssl_var_lookup_ssl_cert
    CERT_KEY_TO_ENV = {
        'version': 'M_VERSION',
        'serialNumber': 'M_SERIAL',
        'notBefore': 'V_START',
        'notAfter': 'V_END',
        'subject': 'S_DN',
        'issuer': 'I_DN',
        'subjectAltName': 'SAN',
        # not parsed by the Python standard library
        # - A_SIG
        # - A_KEY
        # not provided by mod_ssl
        # - OCSP
        # - caIssuers
        # - crlDistributionPoints
    }

    # from mod_ssl/pkg.sslmod/ssl_engine_vars.c ssl_var_lookup_ssl_cert_dn_rec
    CERT_KEY_TO_LDAP_CODE = {
        'countryName': 'C',
        'stateOrProvinceName': 'ST',
        # NOTE: mod_ssl also provides 'stateOrProvinceName' as 'SP'
        # for compatibility with SSLeay
        'localityName': 'L',
        'organizationName': 'O',
        'organizationalUnitName': 'OU',
        'commonName': 'CN',
        'title': 'T',
        'initials': 'I',
        'givenName': 'G',
        'surname': 'S',
        'description': 'D',
        'userid': 'UID',
        'emailAddress': 'Email',
        # not provided by mod_ssl
        # - dnQualifier: DNQ
        # - domainComponent: DC
        # - postalCode: PC
        # - streetAddress: STREET
        # - serialNumber
        # - generationQualifier
        # - pseudonym
        # - jurisdictionCountryName
        # - jurisdictionLocalityName
        # - jurisdictionStateOrProvince
        # - businessCategory
    }

    def __init__(
        self,
        certificate,
        private_key,
        certificate_chain=None,
        ciphers=None,
        *,
        private_key_password=None,
    ):
        """Set up context in addition to base class properties if available."""
        if ssl is None:
            raise ImportError('You must install the ssl module to use HTTPS.')

        super(BuiltinSSLAdapter, self).__init__(
            certificate,
            private_key,
            certificate_chain,
            ciphers,
            private_key_password=private_key_password,
        )

        if private_key_password is None:
            private_key_password = self._prompt_for_tls_password

        self.context = ssl.create_default_context(
            purpose=ssl.Purpose.CLIENT_AUTH,
            cafile=certificate_chain,
        )
        self.context.load_cert_chain(
            certificate,
            private_key,
            password=private_key_password,
        )
        if self.ciphers is not None:
            self.context.set_ciphers(ciphers)

        self._server_env = self._make_env_cert_dict(
            'SSL_SERVER',
            _parse_cert(
                certificate,
                private_key,
                self.certificate_chain,
                private_key_password=private_key_password,
            ),
        )
        if not self._server_env:
            return
        cert = None
        with open(certificate) as f:
            cert = f.read()

        # strip off any keys by only taking the first certificate
        cert_start = cert.find(ssl.PEM_HEADER)
        if cert_start == -1:
            return
        cert_end = cert.find(ssl.PEM_FOOTER, cert_start)
        if cert_end == -1:
            return
        cert_end += len(ssl.PEM_FOOTER)
        self._server_env['SSL_SERVER_CERT'] = cert[cert_start:cert_end]

    @property
    def context(self):
        """:py:class:`~ssl.SSLContext` that will be used to wrap sockets."""
        return self._context

    @context.setter
    def context(self, context):
        """Set the ssl ``context`` to use."""
        self._context = context
        # Python 3.7+
        # if a context is provided via `cherrypy.config.update` then
        # `self.context` will be set after `__init__`
        # use a property to intercept it to add an SNI callback
        # but don't override the user's callback
        # TODO: chain callbacks
        with suppress(AttributeError):
            if ssl.HAS_SNI and context.sni_callback is None:
                context.sni_callback = _sni_callback

    def wrap(self, sock):
        """Wrap and return the given socket, plus WSGI environ entries."""
        sock, _env = super().wrap(  # checks for plaintext http on https port
            sock,
        )

        try:
            s = self.context.wrap_socket(
                sock,
                do_handshake_on_connect=True,
                server_side=True,
            )
        except (
            ssl.SSLEOFError,
            ssl.SSLZeroReturnError,
        ) as tls_connection_drop_error:
            sock.close()
            raise errors.FatalSSLAlert(
                *tls_connection_drop_error.args,
            ) from tls_connection_drop_error
        except ssl.SSLError as generic_tls_error:
            peer_speaks_plain_http_over_https = (
                generic_tls_error.errno == ssl.SSL_ERROR_SSL
                and _assert_ssl_exc_contains(generic_tls_error, 'http request')
            )
            if peer_speaks_plain_http_over_https:
                reraised_connection_drop_exc_cls = errors.NoSSLError
            else:
                reraised_connection_drop_exc_cls = errors.FatalSSLAlert

            sock.close()
            raise reraised_connection_drop_exc_cls(
                *generic_tls_error.args,
            ) from generic_tls_error
        except OSError as tcp_connection_drop_error:
            sock.close()
            raise errors.FatalSSLAlert(
                *tcp_connection_drop_error.args,
            ) from tcp_connection_drop_error

        return s, self.get_environ(s)

    def get_environ(self, sock):
        """Create WSGI environ entries to be merged into each request."""
        cipher = sock.cipher()
        ssl_environ = {
            'wsgi.url_scheme': 'https',
            'HTTPS': 'on',
            'SSL_PROTOCOL': cipher[1],
            'SSL_CIPHER': cipher[0],
            'SSL_CIPHER_EXPORT': '',
            'SSL_CIPHER_USEKEYSIZE': cipher[2],
            'SSL_VERSION_INTERFACE': '%s Python/%s'
            % (
                HTTPServer.version,
                sys.version,
            ),
            'SSL_VERSION_LIBRARY': ssl.OPENSSL_VERSION,
            'SSL_CLIENT_VERIFY': 'NONE',
            # 'NONE' - client did not provide a cert (overriden below)
        }

        # Python 3.3+
        with suppress(AttributeError):
            compression = sock.compression()
            if compression is not None:
                ssl_environ['SSL_COMPRESS_METHOD'] = compression

        # Python 3.6+
        with suppress(AttributeError):
            ssl_environ['SSL_SESSION_ID'] = sock.session.id.hex()
        with suppress(AttributeError):
            target_cipher = cipher[:2]
            for cip in sock.context.get_ciphers():
                if target_cipher == (cip['name'], cip['protocol']):
                    ssl_environ['SSL_CIPHER_ALGKEYSIZE'] = cip['alg_bits']
                    break

        # Python 3.7+ sni_callback
        with suppress(AttributeError):
            ssl_environ['SSL_TLS_SNI'] = sock.sni

        if self.context and self.context.verify_mode != ssl.CERT_NONE:
            client_cert = sock.getpeercert()
            if client_cert:
                # builtin ssl **ALWAYS** validates client certificates
                # and terminates the connection on failure
                ssl_environ['SSL_CLIENT_VERIFY'] = 'SUCCESS'
                ssl_environ.update(
                    self._make_env_cert_dict('SSL_CLIENT', client_cert),
                )
                ssl_environ['SSL_CLIENT_CERT'] = ssl.DER_cert_to_PEM_cert(
                    sock.getpeercert(binary_form=True),
                ).strip()

        ssl_environ.update(self._server_env)

        # not supplied by the Python standard library (as of 3.8)
        # - SSL_SESSION_RESUMED
        # - SSL_SECURE_RENEG
        # - SSL_CLIENT_CERT_CHAIN_n
        # - SRP_USER
        # - SRP_USERINFO

        return ssl_environ

    def _make_env_cert_dict(self, env_prefix, parsed_cert):
        """Return a dict of WSGI environment variables for a certificate.

        E.g. SSL_CLIENT_M_VERSION, SSL_CLIENT_M_SERIAL, etc.
        See https://httpd.apache.org/docs/2.4/mod/mod_ssl.html#envvars.
        """
        if not parsed_cert:
            return {}

        env = {}
        for cert_key, env_var in self.CERT_KEY_TO_ENV.items():
            key = '%s_%s' % (env_prefix, env_var)
            value = parsed_cert.get(cert_key)
            if env_var == 'SAN':
                env.update(self._make_env_san_dict(key, value))
            elif env_var.endswith('_DN'):
                env.update(self._make_env_dn_dict(key, value))
            else:
                env[key] = str(value)

        # mod_ssl 2.1+; Python 3.2+
        # number of days until the certificate expires
        if 'notBefore' in parsed_cert:
            remain = ssl.cert_time_to_seconds(parsed_cert['notAfter'])
            remain -= ssl.cert_time_to_seconds(parsed_cert['notBefore'])
            remain /= 60 * 60 * 24
            env['%s_V_REMAIN' % (env_prefix,)] = str(int(remain))

        return env

    def _make_env_san_dict(self, env_prefix, cert_value):
        """Return a dict of WSGI environment variables for a certificate DN.

        E.g. SSL_CLIENT_SAN_Email_0, SSL_CLIENT_SAN_DNS_0, etc.
        See SSL_CLIENT_SAN_* at
        https://httpd.apache.org/docs/2.4/mod/mod_ssl.html#envvars.
        """
        if not cert_value:
            return {}

        env = {}
        dns_count = 0
        email_count = 0
        for attr_name, val in cert_value:
            if attr_name == 'DNS':
                env['%s_DNS_%i' % (env_prefix, dns_count)] = val
                dns_count += 1
            elif attr_name == 'Email':
                env['%s_Email_%i' % (env_prefix, email_count)] = val
                email_count += 1

        # other mod_ssl SAN vars:
        # - SAN_OTHER_msUPN_n
        return env

    def _make_env_dn_dict(self, env_prefix, cert_value):
        """Return a dict of WSGI environment variables for a certificate DN.

        E.g. SSL_CLIENT_S_DN_CN, SSL_CLIENT_S_DN_C, etc.
        See SSL_CLIENT_S_DN_x509 at
        https://httpd.apache.org/docs/2.4/mod/mod_ssl.html#envvars.
        """
        if not cert_value:
            return {}

        dn = []
        dn_attrs = {}
        for rdn in cert_value:
            for attr_name, val in rdn:
                attr_code = self.CERT_KEY_TO_LDAP_CODE.get(attr_name)
                dn.append('%s=%s' % (attr_code or attr_name, val))
                if not attr_code:
                    continue
                dn_attrs.setdefault(attr_code, [])
                dn_attrs[attr_code].append(val)

        env = {
            env_prefix: ','.join(dn),
        }
        for attr_code, values in dn_attrs.items():
            env['%s_%s' % (env_prefix, attr_code)] = ','.join(values)
            if len(values) == 1:
                continue
            for i, val in enumerate(values):
                env['%s_%s_%i' % (env_prefix, attr_code, i)] = val
        return env

    def makefile(self, sock, mode='r', bufsize=DEFAULT_BUFFER_SIZE):
        """Return socket file object."""
        cls = StreamReader if 'r' in mode else StreamWriter
        return cls(sock, mode, bufsize)
