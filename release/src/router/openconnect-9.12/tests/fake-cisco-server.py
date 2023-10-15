#!/usr/bin/env python3
#
# Copyright © 2021 Daniel Lenski
# Copyright © 2021 Tom Carroll
#
# This file is part of openconnect.
#
# This is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public License
# as published by the Free Software Foundation; either version 2.1 of
# the License, or (at your option) any later version.
#
# This library is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>

import argparse
import ssl
from base64 import b64decode
from flask import Flask, request, session
from textwrap import dedent
import xmltodict
import OpenSSL
from OpenSSL.crypto import _lib, X509
from OpenSSL.crypto import load_certificate, X509Store, X509StoreContext

app = Flask(__name__)
app.config.update(SECRET_KEY=b'fake', DEBUG=True, SESSION_COOKIE_NAME='fake')


########################################

def is_ca_cert(cert):
    for ext in (cert.get_extension(i) for i in range(cert.get_extension_count())):
        if (ext.get_short_name() == b'basicConstraints' and str(ext).find('CA:TRUE') > -1):
            return True
    return False


def get_certs(p7):
    # client-cert is a PKCS7-encoded set of certificates.
    # GnuTLS and OpenSSL order the certificates differently.
    # GnuTLS provides the certificates in 'canonical order',
    # while OpenSSL provides it in the order the programmer
    # added it to the PKCS#7 structure.
    #
    # Testing shows that Cisco servers can handle any order

    if p7.type_is_signed():
        certs = p7._pkcs7.d.sign.cert
    elif p7.type_is_signedAndEnveloped():
        certs = p7._pkcs7.d.signed_and_enveloped.cert
    else:
        return ()

    # Ensure that we have exactly one usercert, and that
    # all the rest are (possibly-intermediate) CA certs
    usercert = None
    extracerts = []
    for i in range(_lib.sk_X509_num(certs)):
        cert = _lib.X509_dup(_lib.sk_X509_value(certs, i))
        pycert = X509._from_raw_x509_ptr(cert)
        if is_ca_cert(pycert):
            extracerts.append(pycert)
        else:
            assert usercert is None
            usercert = pycert
    assert usercert

    # Build a path from the usercert to the root
    path = [usercert]

    # Verify that there are no duplicates in the set
    issuers = {}
    for c in extracerts:
        subject = c.get_subject().der()
        assert subject not in issuers
        issuers[subject] = c

    while True:
        try:
            path.append(issuers.pop(path[-1].get_issuer().der()))
        except KeyError:
            break

    # Verify that there are no remaining (unused) certificates
    assert len(issuers) == 0

    return tuple(path)


def verify_certs(certs, ca_certs):
    # Initialize trust store with CA certificates
    store = X509Store()
    for cert in ca_certs:
        store.add_cert(cert)

    # Incrementally build up trust by first checking intermedaries
    for cert in reversed(certs):
        store_ctx = X509StoreContext(store, cert)
        store_ctx.verify_certificate()
        # Add intermediary to trust
        store.add_cert(cert)

########################################


ALLOWED_HASH_ALGORITHMS = ('sha256', 'sha384', 'sha512')

INITIAL_RESPONSE = dedent('''
    <?xml version="1.0" encoding="UTF-8"?>
    <config-auth client="vpn" type="auth-request" aggregate-auth-version="2">
    <multiple-client-cert-request>{}</multiple-client-cert-request>
    <cert-authenticated></cert-authenticated>
    </config-auth>'''.format(''.join(
        '<hash-algorithm>%s</hash-algorithm>' % algo for algo in ALLOWED_HASH_ALGORITHMS)))

AUTH_COMPLETE_RESPONSE = dedent('''
    <?xml version="1.0" encoding="UTF-8"?>
    <config-auth client="vpn" type="complete" aggregate-auth-version="2">
    <session-id>123456789</session-id>
    <session-token>1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCD</session-token>
    <auth id="success"/>
    <config/>
    </config-auth>''')


# Respond to XML/POST auth requests
@app.route('/', methods=('POST',))
def handle_xmlpost(usergroup=None):
    dict_req = xmltodict.parse(request.data)
    assert 'config-auth' in dict_req
    assert '@client' in dict_req['config-auth'] and dict_req['config-auth']['@client'] == 'vpn'
    assert '@type' in dict_req['config-auth']

    step = dict_req['config-auth']['@type']
    session.update(step=step, authid='main')
    if step == 'init':
        return initial_request(dict_req)
    elif step == 'auth-reply':
        return auth_reply(dict_req)
    else:
        raise AssertionError('Unexpected config-auth/@type %r' % step)


def initial_request(dict_req):
    config_auth = dict_req['config-auth']
    # Expected:
    # <config-auth client="vpn" type="init">
    #   <capabilities>
    #     <auth-method>single-sign-on</auth-method>
    #     <auth-method>single-sign-on-v2</auth-method>
    #     <auth-method>...</auth-method>
    #     <auth-method>multiple-cert</auth-method>
    #   </capabilities>
    # </config-auth>
    assert 'multiple-cert' in config_auth['capabilities']['auth-method']
    return INITIAL_RESPONSE


def auth_reply(dict_req):
    # Expected:
    # <config-auth type="auth-reply">
    #   <auth>
    #     <client-cert-chain cert-store="1M">
    #       <client-cert-sent-via-protocol/>
    #     </client-cert-chain>
    #     <client-cert-chain cert-store="1U">
    #       <client-cert cert-format="pkcs7">${certs_pkcs7}</client-cert>
    #       <client-cert-auth-signature hash-algorithm-chosen="${algo}">${signature}</client-cert-auth-signature>
    #     </client-cert-chain>
    #   </auth>
    # </config-auth>

    config_auth = dict_req['config-auth']
    assert 'client-cert-chain' in config_auth['auth']
    client_cert_chain = config_auth['auth']['client-cert-chain']
    assert client_cert_chain[0]['@cert-store'] == '1M'
    assert client_cert_chain[0]['client-cert-sent-via-protocol'] is None  # empty tag
    assert client_cert_chain[1]['@cert-store'] == '1U'
    assert client_cert_chain[1]['client-cert']['@cert-format'] == 'pkcs7'
    certs_pkcs7 = b64decode(client_cert_chain[1]['client-cert']['#text'])
    signature = b64decode(client_cert_chain[1]['client-cert-auth-signature']['#text'])
    algo = client_cert_chain[1]['client-cert-auth-signature']['@hash-algorithm-chosen']
    assert algo in ALLOWED_HASH_ALGORITHMS

    certs = get_certs(OpenSSL.crypto.load_pkcs7_data(OpenSSL.crypto.FILETYPE_ASN1, certs_pkcs7))
    assert 1 <= len(certs) <= 10

    if app.config['ca_certs']:
        verify_certs(certs, app.config['ca_certs'])

    # Verify that the client has signed the INITIAL_RESPONSE using the private key corresponding to
    # the appropriate certificate (rooted in one of the ca_certs), and using the chosen hash algorithm.
    OpenSSL.crypto.verify(certs[0], signature, INITIAL_RESPONSE.encode(), algo)

    return AUTH_COMPLETE_RESPONSE


def main(args):
    context = ssl.SSLContext()

    # Verify that TLS requests include the appropriate client certificate
    context.load_cert_chain(args.cert, args.key)

    # Read cafile, parsing each certificate found
    ca_certs = []
    if args.cafile:
        with open(args.cafile, 'r') as f:
            root_cas_pem = f.read()

        delimiter = '-----BEGIN CERTIFICATE-----\n'
        offset = 0
        while True:
            offset = root_cas_pem.find(delimiter, offset)
            if offset < 0:
                break
            cert = load_certificate(OpenSSL.crypto.FILETYPE_PEM, root_cas_pem[offset:])
            ca_certs.append(cert)
            offset += len(delimiter)

        assert ca_certs

    app.config['ca_certs'] = ca_certs
    app.run(host=args.host, port=args.port, debug=True, ssl_context=context)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Cisco AnyConnect server stub')
    parser.add_argument('--enable-multicert', action='store_true',
                        help='Enable multiple-certificate authentication')
    parser.add_argument('--cafile', help='Path to CA file')
    parser.add_argument('host', help='Bind address')
    parser.add_argument('port', type=int, help='Bind port')
    parser.add_argument('cert', help='TLS user certificate to validate')
    parser.add_argument('key', nargs='?', help='Key of TLS user certificate to validate')
    args = parser.parse_args()

    if not args.enable_multicert:
        parser.error("This server stub is solely implemented to exercise "
                     "multiple-certificate authentication.")

    main(args)
