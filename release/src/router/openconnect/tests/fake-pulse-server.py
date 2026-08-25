#!/usr/bin/env python3
#
# Copyright © 2026 Ben Walsh
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

########################################
# This program emulates a very simplified authentication flow for a
# Pulse server, and emulates "ping".
########################################

import sys
import logging
import argparse
import struct
import ssl
import socket
import select
import hmac
import hashlib
import subprocess

_logger = logging.getLogger(__name__)

VENDOR_TCG = 0x5597
VENDOR_JUNIPER = 0xa4c
VENDOR_JUNIPER2 = 0x583
IFT_VERSION_REQUEST = 1
IFT_VERSION_RESPONSE = 2
IFT_CLIENT_AUTH_CHALLENGE = 5
IFT_CLIENT_AUTH_RESPONSE = 6
IFT_CLIENT_AUTH_SUCCESS = 7
JUNIPER_1 = (VENDOR_JUNIPER << 8) | 1
EAP_TYPE_EXPANDED = 0xfe
EXPANDED_JUNIPER = (EAP_TYPE_EXPANDED << 24) | VENDOR_JUNIPER
EAP_REQUEST = 1
EAP_SUCCESS = 3
AVP_CODE_EAP_MESSAGE = 79

UDP_PORT = 4500
ESP_ENC_AES_128_CBC = 2
ESP_HMAC_SHA1 = 2
ESP_HMAC_LEN = 12

_status = {}


def _recv_http(conn):
    lines = []
    while True:
        line = conn.readline().decode('iso8859-1').rstrip('\r\n')

        if not line:
            break

        lines.append(line)

    method, uri = lines[0].split(' ')[:2]
    headers = {}
    for line in lines[1:]:  # ignore request line
        parts = line.split(':')
        headers[parts[0].strip().lower()] = parts[1].strip()

    _logger.debug('uri %r http_headers %r', uri, headers)

    len_str = headers.get('content-length')

    data = conn.read(int(len_str)) if len_str else ''

    return method, uri, headers, data


def _send_ift_upgrade(conn):
    conn.write(b'HTTP/1.1 101 Switching Protocols\r\n')
    conn.write(b'\r\n')
    conn.flush()


def _send_status_response(conn):
    content = '&'.join(('%s=%s' % (k, v if isinstance(v, str) else ''))
                       for (k, v) in _status.items()).encode()

    conn.write(b'HTTP/1.1 200\r\n')
    conn.write(('Content-Length: %s\r\n' % len(content)).encode())
    conn.write(b'\r\n')
    conn.write(content)
    conn.flush()


def _set_status(conn, content):
    _logger.debug('content %r', content)

    _status.clear()
    if content:
        for kv in content.decode().split('&'):
            k, v = kv.split('=')
            _status[k] = v

    _send_status_response(conn)


def _recv_ift(conn):
    data = conn.read(12)
    size = struct.unpack('>L', data[8:12])[0]
    data += conn.read(size - len(data))

    return data


def _send_ift(conn, data):
    conn.write(data)
    conn.flush()


def _send_ift_chunked(conn, data):
    # send in chunks -- client should concatenate them
    n = 1
    i = 0
    while i < len(data):
        _send_ift(conn, data[i:i + n])
        i += n
        n = min(n * 2, 1024)


def _expect_ift(conn, want_vendor, want_pkt_type):
    data = _recv_ift(conn)

    vendor, pkt_type = struct.unpack('>LL', data[:8])

    if vendor != want_vendor or pkt_type != want_pkt_type:
        raise ValueError('vendor %x pkt_type %x != vendor %x pkt_type %x'
                         % (vendor, pkt_type, want_vendor, want_pkt_type))

    return data


def _expect_ift_config_udp(conn):
    data = _expect_ift(conn, VENDOR_JUNIPER, 0x01)

    _status['esp_out_spi'] = struct.unpack('<L', data[0x34:0x38])[0]
    _status['esp_out_enc_key'] = data[0x3a:0x4a]
    _status['esp_out_hmac_key'] = data[0x4a:0x5e]
    _status['esp_out_seq'] = 0

    _logger.debug('esp_out_spi = 0x%04x esp_out_enc_key = %r esp_out_hmac_key = %r',
                  _status['esp_out_spi'],
                  _status['esp_out_enc_key'],
                  _status['esp_out_hmac_key'])

    return data


def _send_ift_version(conn):
    _send_ift(conn,
              struct.pack('>LLLLL', VENDOR_TCG,
                          IFT_VERSION_RESPONSE, 0x14, 0, 0x2))


def _send_ift_auth(conn):
    _send_ift(conn,
              struct.pack('>LLLLL', VENDOR_TCG,
                          IFT_CLIENT_AUTH_CHALLENGE, 0x14, 0, JUNIPER_1))


def _send_ift_auth_eap(conn):
    _send_ift(conn,
              struct.pack('>LLLLLHHLL', VENDOR_TCG,
                          IFT_CLIENT_AUTH_CHALLENGE, 0x20, 0, JUNIPER_1,
                          EAP_REQUEST << 8, 0xc, EXPANDED_JUNIPER, 1))


def _send_ift_pass_req(conn):
    eap = struct.pack('>HHLLB', EAP_REQUEST << 8, 12 + 1,
                      EXPANDED_JUNIPER, 2, 1)
    avp = (struct.pack('>LL', AVP_CODE_EAP_MESSAGE, len(eap) + 8)
           + eap)
    _send_ift(conn,
              struct.pack('>LLLLLHHLL', VENDOR_TCG,
                          IFT_CLIENT_AUTH_CHALLENGE, 0x20 + len(avp),
                          0, JUNIPER_1,
                          EAP_REQUEST << 8, 0x0c + len(avp),
                          EXPANDED_JUNIPER, 1)
              + avp)


def _send_ift_auth_cookie(conn):
    cookie = b'c' * 32
    avp = (struct.pack('>LLL', 0xd53, (1 << 31) | 0x2c, VENDOR_JUNIPER2)
           + cookie)
    _send_ift(conn,
              struct.pack('>LLLLLHHLL', VENDOR_TCG,
                          IFT_CLIENT_AUTH_CHALLENGE, 0x20 + len(avp),
                          0, JUNIPER_1,
                          EAP_REQUEST << 8, 0x0c + len(avp),
                          EXPANDED_JUNIPER, 1)
              + avp)


def _send_ift_success(conn):
    _send_ift(conn,
              struct.pack('>LLLLLHH', VENDOR_TCG,
                          IFT_CLIENT_AUTH_SUCCESS, 0x18,
                          0, JUNIPER_1,
                          EAP_SUCCESS << 8, 0x04))


def _send_ift_config(args, conn):
    addr = sum((int(v) << ((3 - i) * 8))
               for i, v in enumerate(args.vpnnet[0].split('.')))
    netmask = (-1 << (32 - int(args.vpnnet[1]))) & 0xffffffff

    # mystery conf
    conf = struct.pack('>HHLHHB', 0x2c00, 0x0d, 0x3000000,
                       0x4026, 1, 0)

    # no routes
    conf += struct.pack('>HHBBBB', 0x2e00, 0x08, 0, 0, 0, 0)

    more_conf = struct.pack('>L', 0x3000000)

    # ip addr
    more_conf += struct.pack('>HHL', 0x0001, 4, addr)

    # netmask
    more_conf += struct.pack('>HHL', 0x0002, 4, netmask)

    # MTU
    more_conf += struct.pack('>HHL', 0x4005, 4, 1400)

    more_conf += struct.pack('>HHH', 0x4010, 2, ESP_ENC_AES_128_CBC)

    more_conf += struct.pack('>HHH', 0x4011, 2, ESP_HMAC_SHA1)

    more_conf += struct.pack('>HHH', 0x4016, 2, UDP_PORT)

    conf += struct.pack('>L', 4 + len(more_conf)) + more_conf

    _send_ift(conn,
              struct.pack('>LLLLLLLLLLL', VENDOR_JUNIPER, 1, 0x2c + len(conf),
                          0, 0, 0, 0, 0, 0x2e20f000, 0, 0x1c + len(conf))
              + conf)


def _send_ift_config_udp(conn):
    _status['esp_in_spi'] = 0x12345678
    _status['esp_in_enc_key'] = b'e' * 16
    _status['esp_in_hmac_key'] = b'h' * 20

    more_conf = (struct.pack('>L', 0x01000000)
                 + struct.pack('<L', _status['esp_in_spi'])
                 + struct.pack('>H', 0x40)
                 + _status['esp_in_enc_key'] + _status['esp_in_hmac_key']
                 + (b'\0' * (0x46 - len(_status['esp_in_enc_key'])
                             - len(_status['esp_in_hmac_key']))))

    conf = struct.pack('>L', 4 + len(more_conf)) + more_conf

    _send_ift(conn,
              struct.pack('>LLLLLLLLLLL', VENDOR_JUNIPER, 1, 0x2c + len(conf),
                          0, 0, 0, 0, 0, 0x21202400, 0, 0x1c + len(conf))
              + conf)


def _send_ift_config_end(conn):
    _send_ift(conn,
              struct.pack('>LLLLL', VENDOR_JUNIPER, 0x8f, 0x14, 0, 0))


def _cksum(bs):
    if len(bs) % 2:
        bs += b'\0'

    s = 0
    for i in range(0, len(bs), 2):
        s += (bs[i] << 8) | bs[i + 1]

    s = (s & 0xffff) + (s >> 16)
    s += s >> 16

    s = ~s & 0xffff

    return bytearray([s >> 8, s & 0xff])


def _handle_ping(ip_msg):
    if ip_msg[9] != 1:  # ICMP
        return None

    if ip_msg[20] != 8:  # ping
        return None

    _logger.debug('received ping')

    # zero checksums
    ip_msg[10:12] = (0, 0)
    ip_msg[22:24] = (0, 0)

    src_addr = ip_msg[12:16]
    dst_addr = ip_msg[16:20]

    ip_msg[12:16] = dst_addr
    ip_msg[16:20] = src_addr
    ip_msg[20] = 0  # ping reply

    ip_msg[10:12] = _cksum(ip_msg[0:20])
    ip_msg[22:24] = _cksum(ip_msg[20:])

    return ip_msg


def _handle_ssl_tunnel(args, conn):
    data = _recv_ift(conn)

    if data is None:
        return False

    vendor, pkt_type = struct.unpack('>LL', data[:8])

    if vendor != VENDOR_JUNIPER:
        return True

    if pkt_type == 0x89:  # close connection
        return False

    if pkt_type != 4:
        return True

    ip_pkt = _handle_ping(bytearray(data[16:]))
    if not ip_pkt:
        return True

    # send chunks, to test "short read" handling code
    _send_ift_chunked(
        conn,
        struct.pack('>LLLL', VENDOR_JUNIPER, 4, 0x10 + len(ip_pkt), 0)
        + bytes(ip_pkt))

    _status['ssl_ping'] = 'true'

    return True


def _hex(bs):
    return ''.join(('%02x' % b) for b in bs)


def _aes_128_cbc(data, key, iv, decrypt=False):
    # FIXME: Use "Crypto" from package "python3-pycryptodome"

    cmd = (['openssl', 'aes-128-cbc']
           + (['-d'] if decrypt else [])
           + ['-nopad', '-K', _hex(key), '-iv', _hex(iv)])

    _logger.debug('%s', ' '.join(cmd))

    res = subprocess.run(cmd, input=data, stdout=subprocess.PIPE, check=True)

    return res.stdout


def _handle_udp_tunnel(usock):
    data, addr = usock.recvfrom(4096)

    mac = hmac.new(_status['esp_in_hmac_key'], data[:-ESP_HMAC_LEN],
                   hashlib.sha1).digest()[:ESP_HMAC_LEN]

    if mac != data[-ESP_HMAC_LEN:]:
        raise ValueError('HMAC mismatch %r vs %r'
                         % (mac, data[-ESP_HMAC_LEN:]))

    pkt = _aes_128_cbc(data[24:-ESP_HMAC_LEN], _status['esp_in_enc_key'],
                       data[8:24], decrypt=True)

    if pkt[-1] != 0x04:
        return True

    pkt = pkt[:-pkt[-2] - 2]  # remove padding

    if pkt != b'\0':  # probe
        ip_pkt = _handle_ping(bytearray(pkt))
        if not ip_pkt:
            return True

        pkt = bytes(ip_pkt)

        _status['udp_ping'] = 'true'

    padlen = 15 - ((len(pkt) + 1) % 16)

    data = pkt + bytes(list(range(1, padlen + 1)) + [padlen, 0x04])

    iv = b'i' * 16

    data = (struct.pack('>LL', _status['esp_out_spi'], _status['esp_out_seq'])
            + iv
            + _aes_128_cbc(data, _status['esp_out_enc_key'], iv))

    data += hmac.new(_status['esp_out_hmac_key'], data,
                     hashlib.sha1).digest()[:ESP_HMAC_LEN]

    usock.sendto(data, addr)

    _status['esp_out_seq'] += 1

    return True


def _handle_tunnels(args, csock, conn, usock):
    fps = select.select([csock, usock], [], [])[0]

    for fp in fps:
        # select on csock (which has fileno), but read conn
        res = (_handle_ssl_tunnel(args, conn) if fp == csock
               else _handle_udp_tunnel(usock))
        if not res:
            return False

    return True


def _communicate(args, csock, conn, usock):
    method, uri, http_headers, http_content = _recv_http(conn)

    if uri == '/STATUS':
        _send_status_response(conn)
        return
    elif uri == '/CONFIGURE':
        _set_status(conn, http_content)
        return

    _send_ift_upgrade(conn)

    _expect_ift(conn, VENDOR_TCG, IFT_VERSION_REQUEST)

    _send_ift_version(conn)

    _expect_ift(conn, VENDOR_JUNIPER, 0x88)  # client capabilities

    _send_ift_auth(conn)

    _expect_ift(conn, VENDOR_TCG, IFT_CLIENT_AUTH_RESPONSE)  # "anonymous"

    _send_ift_auth_eap(conn)

    _expect_ift(conn, VENDOR_TCG, IFT_CLIENT_AUTH_RESPONSE)  # client info

    _send_ift_pass_req(conn)

    _expect_ift(conn, VENDOR_TCG, IFT_CLIENT_AUTH_RESPONSE)  # client user/pass

    _send_ift_auth_cookie(conn)

    _expect_ift(conn, VENDOR_TCG, IFT_CLIENT_AUTH_RESPONSE)  # client ok

    _send_ift_success(conn)

    _send_ift_config(args, conn)

    if _status.get('enable_udp') == 'true':
        _send_ift_config_udp(conn)

        _expect_ift_config_udp(conn)

        _expect_ift(conn, VENDOR_JUNIPER, 0x05)  # "ncmo=1"

    _send_ift_config_end(conn)

    while _handle_tunnels(args, csock, conn, usock):
        pass

    _logger.info('closing connection')


def _run(args, ssock, usock):
    while True:
        csock, addr = ssock.accept()
        with csock.makefile('rwb') as conn:
            _communicate(args, csock, conn, usock)


def main():
    parser = argparse.ArgumentParser()

    parser.add_argument('host')
    parser.add_argument('port', type=int)
    parser.add_argument('vpnnet', type=lambda s: s.split('/'))
    parser.add_argument('certfile')
    parser.add_argument('keyfile', nargs='?')

    args = parser.parse_args()

    logging.basicConfig(level=logging.DEBUG)

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(args.certfile, args.keyfile)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0) as sock:
        sock.bind((args.host, args.port))
        sock.listen(5)
        with context.wrap_socket(sock, server_side=True) as ssock:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as usock:
                usock.bind((args.host, UDP_PORT))
                _run(args, ssock, usock)

    return 0


if __name__ == '__main__':
    sys.exit(main())
