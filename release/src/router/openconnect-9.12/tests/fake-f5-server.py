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
# This program emulates the authentication-phase behavior of a F5
# server enough to test OpenConnect's authentication behavior against it.
# Specifically, it emulates the following requests:
#
#    GET /
#    GET /my.policy
#    POST /my.policy
#
# It does not actually validate the credentials in any way, but attempts to
# verify their consistency from one request to the next, by saving their
# values via a (cookie-based) session.
########################################

import sys
import ssl
import random
import base64
import time
from json import dumps
from functools import wraps
from flask import Flask, request, redirect, url_for, make_response, session
from dataclasses import dataclass

host, port, *cert_and_maybe_keyfile = sys.argv[1:]

context = ssl.SSLContext()
context.load_cert_chain(*cert_and_maybe_keyfile)

app = Flask(__name__)
app.config.update(SECRET_KEY=b'fake', DEBUG=True, HOST=host, PORT=int(port), SESSION_COOKIE_NAME='fake')


########################################

def cookify(jsonable):
    return base64.urlsafe_b64encode(dumps(jsonable).encode())


def require_MRHSession(fn):
    @wraps(fn)
    def wrapped(*args, **kwargs):
        if not request.cookies.get('MRHSession'):
            session.clear()
            return redirect(url_for('get_policy'))
        return fn(*args, **kwargs)
    return wrapped


def check_form_against_session(*fields, use_query=False):
    def inner(fn):
        @wraps(fn)
        def wrapped(*args, **kwargs):
            source = request.args if use_query else request.form
            source_name = 'args' if use_query else 'form'
            for f in fields:
                assert session.get(f) == source.get(f), \
                    f'at step {session.get("step")}: {source_name} {f!r} {source.get(f)!r} != session {f!r} {session.get(f)!r}'
            return fn(*args, **kwargs)
        return wrapped
    return inner

########################################

# Configure the fake server. These settings will persist unless/until reconfigured or restarted:
#   domains: Comma-separated list of domains/authgroups to offer
#   mock_dtls: Advertise DTLS capability (default False)
#   no_html_login_form: Don't include a proper HTML login form (default False), with 'auth_form.username' and 'auth_form.password' fields
#   hidden_form_then_2fa: After the login form is completed:
#      1. Send a hidden_form with 'hidden_form.choice' fields
#      2. Then send a 2FA form, with 'auth_form.username' and 'auth_form.otp_password' fields
#   hidden_required_value: If set, then the 'hidden_form.choice' field must be overridden to this specific value
#     (using '--form-entry hidden_form.choice=VALUE'; see https://gitlab.com/openconnect/openconnect/-/issues/493#note_1098016112
#     for use of this in a real F5 VPN)
@dataclass
class TestConfiguration:
    domains: list = ()
    mock_dtls: bool = False
    no_html_login_form: bool = False
    hidden_form_then_2fa: bool = False
    hidden_required_value: str = None
    def __post_init__(self):
        if self.domains:
            assert not self.no_html_login_form, "Cannot set 'domains' with 'no_html_login_form=True'"
        if self.hidden_required_value is not None:
            assert self.hidden_form_then_2fa, "Cannot set 'hidden_required_value' without 'hidden_form_then_2fa'"
C = TestConfiguration()


@app.route('/CONFIGURE', methods=('POST', 'GET'))
def configure():
    global C
    if request.method == 'POST':
        C = TestConfiguration(
            domains=request.form['domains'].split(',') if 'domains' in request.form else (),
            mock_dtls=bool(request.form.get('mock_dtls')),
            no_html_login_form=bool(request.form.get('no_html_login_form')),
            hidden_form_then_2fa=bool(request.form.get('hidden_form_then_2fa')),
            hidden_required_value=request.form.get('hidden_required_value'))
        return '', 201
    else:
        return 'Current configuration of fake F5 server configuration:\n{}\n'.format(C)


# Respond to initial 'GET /' with a redirect to '/my.policy'
@app.route('/')
def root():
    session.update(step='initial-GET')
    return redirect(url_for('get_policy'))


# Respond to 'GET /my.policy with a login form
@app.route('/my.policy')
def get_policy():
    session.update(step='GET-login-form')
    if C.no_html_login_form:
        json = dumps({
            "logon": {
                "form": {
                    "id": "auth_form",
                    "title": "Fake JSON login form",
                    "fields": [
                        {"type": "text", "name": "username", "caption": "Username"},
                        {"type": "password", "name": "password", "caption": "Password"}
                    ]
                }
            }
        }, indent='  ')
        return f'''<html><head><script type="text/javascript">appLoader.configure({json});</script></head>
<body>It would be nice if F5 login pages consistently used actual HTML forms</body></html>'''

    sel = ''
    if C.domains:
        sel = '<select name="domain">%s</select>' % ''.join(
            '<option value="%d">%s</option>' % nv for nv in enumerate(C.domains))

    return '''
<html><body><form id="auth_form" method="post">
<table><tr><td id="credentials_table_header">Fake HTML login form</td></tr></table>
<input type="text" name="username"/>
<input type="password" name="password"/>
%s</form></body></html>''' % sel


# Respond to 'POST /my.policy with a redirect response containing MRHSession and F5_ST
# cookies (OpenConnect uses the combination of the two to detect successful authentication)
@app.route('/my.policy', methods=['POST'])
def post_policy():
    if C.hidden_form_then_2fa:
        if session.get('step') == 'GET-login-form':
            # Initial login form
            session.update(step='POST-login-form-get-hidden-form')

        elif session.get('step') == 'POST-login-form-get-hidden-form':
            # We're submitting the hidden form.
            # Fling back to the login form if the hidden field doesn't have the
            # expected/magic value. See https://gitlab.com/openconnect/openconnect/-/issues/493
            if C.hidden_required_value is not None and request.form.get('choice') != C.hidden_required_value:
                return redirect(url_for('get_policy'))

            # Success. Continue to the 2FA form.
            session.update(step='POST-hidden-form-get-2fa-form')
            return '''
<html><body>
<form method="post" id="auth_form" name="auth_form" action="">
<input type='password' name='otp_password' value=''>
</form></body></html>'''

        elif session.get('step') == 'POST-hidden-form-get-2fa-form':
            # We're successfully submitting the 2FA form
            session.update(step='POST-2fa-form', otp_password=request.form.get('otp_password'))

        else:
            assert f"Unexpected step {session.get('step')!r} for hidden form/2FA"

    else:
        session.update(step='POST-login-form')

    if C.domains:
        assert 0 <= int(request.form.get('domain', -1)) < len(C.domains)
    session.update(username=request.form.get('username'),
                   password=request.form.get('password'),
                   domain=request.form.get('domain'))

    if session['step'] == 'POST-login-form-get-hidden-form':
        return '''
<html><body>
<a href="#" onclick="javascript:var f=document.getElementById('hidden_form');f.my_result.value=1;f.submit();">Click here to submit hidden form with changed value of hidden field</a>
<form method="post" id="hidden_form" name="hidden_form" action="">
<input type='hidden' id="my_result" value='0' name='choice'>
</form></body></html>'''

    resp = redirect(url_for('webtop'))
    resp.set_cookie('MRHSession', cookify(dict(session)))
    resp.set_cookie('F5_ST', '1z1z1z%dz%d' % (time.time(), 3600))
    return resp


@app.route('/vdesk/webtop.eui')
def webtop():
    session.update(step='POST-login-webtop')
    # print(session)

    return 'some junk HTML webtop'


# Respond to 'GET /vdesk/vpn/index.php3?outform=xml&client_version=2.0 with an XML config
# [Save VPN resource name in the session for verification of client state later]
@app.route('/vdesk/vpn/index.php3')
@require_MRHSession
def profile_params():
    assert request.args.get('outform') == 'xml' and request.args.get('client_version') == '2.0'
    vpn_name = 'demo%d_vpn_resource' % random.randint(1, 100)
    session.update(step='GET-profile-params', resourcename='/Common/'+vpn_name)

    return (f'''
            <?xml version="1.0" encoding="utf-8"?>
            <favorites type="VPN" limited="YES">
              <favorite id="/Common/{vpn_name}">
                <caption>{vpn_name}</caption>
                <name>/Common/{vpn_name}</name>
                <params>resourcename=/Common/{vpn_name}</params>
              </favorite>
            </favorites>''',
            {'content-type': 'application/xml'})

# Respond to 'GET /vdesk/vpn/connect.php3?outform=xml&client_version=2.0&resourcename=RESOURCENAME
# with an ugliest-XML-you've-ever-seen config.
# [Save random HDLC flag and ur_Z for verification later.]
@app.route('/vdesk/vpn/connect.php3')
@require_MRHSession
@check_form_against_session('resourcename', use_query=True)
def options():
    assert request.args.get('outform') == 'xml' and request.args.get('client_version') == '2.0'
    session.update(hdlc_framing=['no', 'yes'][random.randint(0, 1)],
                   Z=session['resourcename'] + str(random.randint(1, 100)),
                   ipv4='yes', ipv6=['no', 'yes'][random.randint(0, 1)],
                   sess=request.cookies['MRHSession'] + str(random.randint(1, 100)))

    return (f'''
            <?xml version="1.0" encoding="UTF-8" ?><favorite>
            <object ID="ur_Host" CLASSID="CLSID:CC85ACDF-B277-486F-8C70-2C9B2ED2A4E7"
             CODEBASE="https://{app.config['HOST']}:{app.config['PORT']}/vdesk/terminal/urxshost.cab"
             WIDTH="320" HEIGHT="240">
                <ur_Z>{session['Z']}</ur_Z>
                <Session_ID>{session['sess']}</Session_ID>
                <ur_name>{session['resourcename']}</ur_name>
                <host0>{app.config['HOST']}</host0>
                <port0>{app.config['PORT']}</port0>
                <tunnel_host0>{app.config['HOST']}</tunnel_host0>
                <tunnel_port0>{app.config['PORT']}</tunnel_port0>
                <tunnel_protocol0>https</tunnel_protocol0>
                <idle_session_timeout>900</idle_session_timeout>
                <IPV4_0>{int(session['ipv4']=='yes')}</IPV4_0>
                <IPV6_0>{int(session['ipv6']=='yes')}</IPV6_0>
                <tunnel_dtls>{int(C.mock_dtls)}</tunnel_dtls>
                <tunnel_port_dtls>{app.config['PORT']}</tunnel_port_dtls>

                <DNS0>1.1.1.1</DNS0>
                <DNS1>8.8.8.8</DNS1>
                <DNS6_0>2606:4700:4700::1111</DNS6_0>
                <DNS6_1>2001:4860:4860::8888</DNS6_1>
                <WINS0></WINS0>
                <DNSSuffix0>foo.com</DNSSuffix0>
                <SplitTunneling0>2</SplitTunneling0>
                <LAN0>10.11.10.10/32 10.11.1.0/24</LAN0>
                <LAN6_0>::/1 8000::/1</LAN6_0>

                <DNS_SPLIT0>*</DNS_SPLIT0>

                <hdlc_framing>{session['hdlc_framing']}</hdlc_framing>
            </object>
            </favorite>''',
            {'content-type': 'application/xml'})


# Respond to faux-CONNECT 'GET /myvpn' with 504 Gateway Timeout
# (what the real F5 server responds with when it doesn't like the parameters, intended
# to trigger "cookie rejected" error in OpenConnect)
@app.route('/myvpn')
# Can't use because OpenConnect doesn't send cookies here (see f5.c for why)
# @check_form_against_session('sess', 'hdlc_framing', 'ipv4', 'ipv6', 'Z', use_query=True)
def tunnel():
    try:
        base64.urlsafe_b64decode(request.args.get('hostname') or None)
    except (ValueError, TypeError):
        raise AssertionError('Hostname is not a base64 string')
    return make_response('', 504, {'X-VPN-Client-IP': '10.11.1.2', 'X-VPN-Client-IPv6': '2601::f00f:1234'})


# Respond to 'GET /remote/logout' by clearing session and MRHSession
@app.route('/vdesk/hangup.php3')
@require_MRHSession
def logout():
    assert request.args.get('hangup_error') == '1'
    session.clear()
    resp = make_response('successful logout')
    resp.set_cookie('MRHSession', '')
    return resp


app.run(host=app.config['HOST'], port=app.config['PORT'], debug=app.config['DEBUG'],
        ssl_context=context, use_debugger=False)
