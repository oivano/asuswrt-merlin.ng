#!/usr/bin/env python3
#
# Copyright © 2021 Daniel Lenski
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
# This program emulates the authentication-phase behavior of a Fortinet
# server enough to test OpenConnect's authentication behavior against it.
# Specifically, it emulates the following requests:
#
#    GET /[$REALM]
#    GET /remote/login[?realm=$REALM]
#    POST /remote/logincheck (with username and credential fields)
#      No 2FA)   Completes the login
#      With 2FA) Returns a 2FA challenge
#    POST /remote/logincheck (with username and 2FA response fields)
#
# It does not actually validate the credentials in any way, but attempts to
# verify their consistency from one request to the next, by saving their
# values via a (cookie-based) session.
########################################

import sys
import ssl
import random
import base64
from json import dumps
from functools import wraps
from flask import Flask, request, abort, redirect, url_for, make_response, session
from dataclasses import dataclass

host, port, *cert_and_maybe_keyfile = sys.argv[1:]

context = ssl.SSLContext()
context.load_cert_chain(*cert_and_maybe_keyfile)

app = Flask(__name__)
app.config.update(SECRET_KEY=b'fake', DEBUG=True, HOST=host, PORT=int(port), SESSION_COOKIE_NAME='fake')


########################################

def cookify(jsonable):
    return base64.urlsafe_b64encode(dumps(jsonable).encode())


def require_SVPNCOOKIE(fn):
    @wraps(fn)
    def wrapped(*args, **kwargs):
        if not request.cookies.get('SVPNCOOKIE'):
            session.clear()
            return redirect(url_for('login'))
        return fn(*args, **kwargs)
    return wrapped


def check_form_against_session(*fields):
    def inner(fn):
        @wraps(fn)
        def wrapped(*args, **kwargs):
            for f in fields:
                assert session.get(f) == request.form.get(f), \
                    f'at step {session.get("step")}: form {f!r} {request.form.get(f)!r} != session {f!r} {session.get(f)!r}'
            return fn(*args, **kwargs)
        return wrapped
    return inner

########################################

# Configure the fake server. These settings will persist unless/until reconfigured or restarted:
#   want_2fa: Require 2FA (default 0)
#     If want_2fa>1, multiple rounds of 2FA token entry will be required.
#   type_2fa: 2FA format (either 'tokeninfo', 'ftmpush', or 'html'; 'tokeninfo' is the default)
@dataclass
class TestConfiguration:
    want_2fa: int = 0
    type_2fa: str = None
C = TestConfiguration()


@app.route('/CONFIGURE', methods=('POST', 'GET'))
def configure():
    global C
    if request.method == 'POST':
        C = TestConfiguration(
            want_2fa=int(request.form.get('want_2fa', 0)),
            type_2fa=request.form.get('type_2fa', 'tokeninfo'))
        return '', 201
    else:
        return 'Current configuration of fake Fortinet server:\n{}\n'.format(C)


# Respond to initial 'GET /' with a login form
# Respond to initial 'GET /<realm>' with a redirect to '/remote/login?realm=<realm>'
# [Save want_2fa configuration parameter in session so that we can count down multiple rounds of it]
@app.route('/')
@app.route('/<realm>')
def realm(realm=None):
    session.update(step='GET-realm', want_2fa=C.want_2fa)
    # print(session)
    if realm:
        return redirect(url_for('login', realm=realm, lang='en'))
    else:
        return login()


# Respond to 'GET /remote/login?realm=<realm>' with a placeholder stub (since OpenConnect doesn't even try to parse the form)
# [Save realm in the session for verification of client state later]
@app.route('/remote/login')
def login():
    realm = request.args.get('realm')
    session.update(step='GET-login-form', realm=realm or '')
    return f'login page for realm {realm!r}'


# Respond to 'POST /remote/logincheck'
@app.route('/remote/logincheck', methods=['POST'])
def logincheck():
    want_2fa = session.get('want_2fa')
    if want_2fa:
        if (   (C.type_2fa == 'tokeninfo' and request.form.get('username') and request.form.get('code'))
            or (C.type_2fa == 'ftmpush' and request.form.get('username') and request.form.get('ftmpush') == '1' and not request.form.get('magic'))
            or (C.type_2fa == 'html' and request.form.get('username') and request.form.get('magic') and request.form.get('credential'))):
            # we've received (at least one round of) 2FA login
            if want_2fa == 1:
                return complete_2fa()
            else:
                session.update(want_2fa=want_2fa - 1)
                return send_2fa_html() if C.type_2fa == 'html' else send_2fa_tokeninfo()
        elif request.form.get('username') and request.form.get('credential'):
            # we've just received the initial non-2FA login
            return send_2fa_html() if C.type_2fa == 'html' else send_2fa_tokeninfo()
    elif (request.form.get('username') and request.form.get('credential')):
        return complete_non_2fa()
    abort(405)


# 2FA completion: ensure that client has parroted back the same values
# for username, reqid, polid, grp/grpid, portal, magic
# [Save code in the session for potential use later]
@check_form_against_session('username', 'reqid', 'polid', 'grp', 'grpid', 'portal', 'magic')
def complete_2fa():
    session.update(step='complete-2FA', code=request.form.get('code'))
    # print(session)

    resp = make_response('ret=1,redir=/remote/fortisslvpn_xml')
    resp.set_cookie('SVPNCOOKIE', cookify(dict(session)))
    return resp


# Tokeninfo-based 2FA initial login: ensure that client has sent the right realm value, and
# reply with a tokeninfo challenge containing all known fields.
# [Save username, credential, and challenge fields in the session for verification of client state later]
@check_form_against_session('realm')
def send_2fa_tokeninfo():
    global C
    if C.type_2fa == 'ftmpush':
        tokeninfo = 'ftm_push'
        msg = 'Leave blank to simulate fake FTM push'
        magic = None
    else:
        tokeninfo = ''
        msg = 'Please enter your tokeninfo code'
        magic = '1-'+str(random.randint(10_000_000, 99_000_000))
    session.update(step='send-2FA-tokeninfo', username=request.form.get('username'), credential=request.form.get('credential'),
                   reqid=str(random.randint(10_000_000, 99_000_000)), polid='1-1-'+str(random.randint(10_000_000, 99_000_000)),
                   magic=magic, portal=random.choice('ABCD'), grp=random.choice('EFGH'))
    # print(session)

    return ('ret=2,reqid={reqid},polid={polid},grp={grp},portal={portal},magic={magic},'
            'tokeninfo={tokeninfo},chal_msg={msg} ({want_2fa} remaining)'.format(tokeninfo=tokeninfo, msg=msg, **session),
            {'content-type': 'text/plain'})


# HTML-based 2FA initial login: ensure that client has sent the right realm value, and
# reply with an HTML challenge containing all known fields.
# [Save username, credential, and challenge fields in the session for verification of client state later]
@check_form_against_session('realm')
def send_2fa_html():
    global C
    session.update(step='send-2FA-html', username=request.form.get('username'), credential=request.form.get('credential'),
                   reqid=str(random.randint(10_000_000, 99_000_000)), grpid='0,'+str(random.randint(1_000, 9_999))+',1',
                   magic='1-'+str(random.randint(10_000_000, 99_000_000)))
    # print(session)

    return ('''
        <html><body><form action="{logincheck}" method="POST">
        <b>Please enter your HTML 2FA code ({want_2fa} remaining)</b>
        <input type="hidden" name="magic" value="{magic}">
        <input type="hidden" name="username" value="{username}">
        <input type="hidden" name="reqid" value="{reqid}">
        <input type="hidden" name="grpid" value="{grpid}">
        <input type="password" name="credential">
        <input class="button" type="submit" value="OK">
        </form></body></html>
        '''.format(logincheck=url_for('logincheck'), **session),
        401,
        {'content-type': 'text/html'})


# Non-2FA login: ensure that client has sent the right realm value
@check_form_against_session('realm')
def complete_non_2fa():
    session.update(step='complete-non-2FA', username=request.form.get('username'), credential=request.form.get('credential'))
    # print(session)

    resp = make_response('ret=1,redir=/remote/fortisslvpn_xml', {'content-type': 'text/plain'})
    resp.set_cookie('SVPNCOOKIE', cookify(dict(session)))
    return resp


# Respond to 'GET /fortisslvpn with a placeholder stub (since OpenConnect doesn't even try to parse this)
@app.route('/remote/fortisslvpn')
@require_SVPNCOOKIE
def html_config():
    return 'VPN config in HTML format'


# Respond to 'GET /fortisslvpn_xml with a fake config
@app.route('/remote/fortisslvpn_xml')
@require_SVPNCOOKIE
def xml_config():
    dual_stack = request.args.get('dual_stack') not in (None, '0')
    resp = make_response(f'''
            <?xml version="1.0" encoding="utf-8"?>
            <sslvpn-tunnel ver="2" dtls="1" patch="1">
              <dtls-config heartbeat-interval="10" heartbeat-fail-count="10" heartbeat-idle-timeout="10" client-hello-timeout="10"/>
              <tunnel-method value="ppp"/>
              <tunnel-method value="tun"/>
              <fos platform="FakeFortigate" major="1" minor="2" patch="3" build="4567" branch="4567" mr_num="??"/>
              <auth-ses tun-connect-without-reauth="1" check-src-ip="0" tun-user-ses-timeout="240"/>
              <ipv4>
                <dns ip="1.1.1.1"/>
                <dns ip="8.8.8.8" domain="foo.com"/>
                <split-dns domains='mydomain1.local,mydomain2.local' dnsserver1='10.10.10.10' dnsserver2='10.10.10.11' />
                <assigned-addr ipv4="10.11.1.123"/>
                <split-tunnel-info>
                  <addr ip="10.11.10.10" mask="255.255.255.255"/>
                  <addr ip="10.11.1.0" mask="255.255.255.0"/>
                </split-tunnel-info>
                <split-tunnel-info negate="1">
                  <addr ip="9.9.9.9" mask="255.255.255.255"/>
                </split-tunnel-info>
              </ipv4>
              {"<ipv6>" if dual_stack else "<--"}
                <dns ipv6="cafe:1234::5678"/>
                <assigned-addr ipv6="faff:ffff::1" prefix-len="64"/>
                <split-tunnel-info>
                  <addr ipv6="fdff:ffff::" prefix-len="120"/>
                </split-tunnel-info>
                <split-tunnel-info negate="1">
                  <addr ipv6="2620:fe::fe" prefix-len="128"/>
                </split-tunnel-info>
              {"</ipv6>" if dual_stack else "-->"}
              <idle-timeout val="3600"/>
              <auth-timeout val="18000"/>
            </sslvpn-tunnel>''',
            {'content-type': 'application/xml'})
    # Re-set the SVPNCOOKIE (this was causing a crash: https://gitlab.com/openconnect/openconnect/-/issues/514)
    resp.set_cookie('SVPNCOOKIE', request.cookies['SVPNCOOKIE'])
    return resp


# Respond to faux-CONNECT 'GET /remote/sslvpn-tunnel' with 403 Forbidden
# (what the real Fortinet server sends when it doesn't like the parameters,
# intended to trigger "cookie rejected" error in OpenConnect)
@app.route('/remote/sslvpn-tunnel')
@require_SVPNCOOKIE
def tunnel():
    abort(403)


# Respond to 'GET /remote/logout' by clearing session and SVPNCOOKIE
@app.route('/remote/logout')
@require_SVPNCOOKIE
def logout():
    session.clear()
    resp = make_response('successful logout')
    resp.set_cookie('SVPNCOOKIE', '')
    return resp


app.run(host=app.config['HOST'], port=app.config['PORT'], debug=app.config['DEBUG'],
        ssl_context=context, use_debugger=False)
