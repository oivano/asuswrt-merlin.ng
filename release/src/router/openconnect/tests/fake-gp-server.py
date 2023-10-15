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

import sys
import ssl
from random import randint, choice
import base64
from json import dumps
from html import escape
from functools import wraps
from flask import Flask, request, abort, url_for, session
from dataclasses import dataclass

host, port, *cert_and_maybe_keyfile = sys.argv[1:]

context = ssl.SSLContext()
context.load_cert_chain(*cert_and_maybe_keyfile)

app = Flask(__name__)
app.config.update(SECRET_KEY=b'fake', DEBUG=True, HOST=host, PORT=int(port), SESSION_COOKIE_NAME='fake')


########################################

def cookify(jsonable):
    return base64.urlsafe_b64encode(dumps(jsonable).encode())


def check_form_against_session(*fields, use_query=False, on_failure=None):
    def inner(fn):
        @wraps(fn)
        def wrapped(*args, **kwargs):
            source = request.args if use_query else request.form
            source_name = 'args' if use_query else 'form'
            for f in fields:
                fs = f.replace('_', '-')
                if on_failure:
                    if session.get(f) != source.get(fs):
                        return on_failure
                else:
                    assert session.get(f) == source.get(fs), \
                        f'at step {session.get("step")}: {source_name} {f!r} {source.get(fs)!r} != session {f!r} {session.get(f)!r}'
            return fn(*args, **kwargs)
        return wrapped
    return inner

########################################


if_path2name = {'global-protect': 'portal', 'ssl-vpn': 'gateway'}

# Configure the fake server. These settings will persist unless/until reconfigured or restarted:
#   gateways: list of gateway names for portal to offer (all will point to same HOST:PORT as portal)
#   {portal_2fa, gw_2fa}: require challenge-based 2FA to complete {/global-protect/getconfig.esp, /ssl-vpn/login.esp} request
#     '': disabled
#     xml: XML-based challenge
#     js: JavaScript challenge
#     html: JavaScript-wrapped-in-HTML challenge
#     <any other value>: random
#   portal_saml: set to 'portal-userauthcookie' or 'prelogin-cookie' to require SAML on portal (and
#                expect the named cookie to be provided to signal SAML completion)
#   gateway_saml: likewise, set to require SAML on gateway
#   portal_cookie: if set (to 'portal-userauthcookie' or 'portal-prelogonuserauthcookie'), then
#                  the portal getconfig response will include the named "cookie" field which should
#                  be used to automatically continue login on the gateway
@dataclass
class TestConfiguration:
    gateways: list = ('Default gateway',)
    portal_2fa: str = None
    gw_2fa: str = None
    portal_cookie: str = None
    portal_saml: str = None
    gateway_saml: str = None
C = TestConfiguration()
OUTSTANDING_SAML_TOKENS = set()


@app.route('/CONFIGURE', methods=('POST', 'GET'))
def configure():
    global C
    if request.method == 'POST':
        gateways, portal_2fa, gw_2fa, portal_cookie, portal_saml, gateway_saml = request.form.get('gateways'), request.form.get('portal_2fa'), request.form.get('gw_2fa'), request.form.get('portal_cookie'), request.form.get('portal_saml'), request.form.get('gateway_saml')
        C.gateways = gateways.split(',') if gateways else ('Default gateway',)
        C.portal_cookie = portal_cookie
        C.portal_2fa = portal_2fa and portal_2fa.strip().lower()
        C.gw_2fa = gw_2fa and gw_2fa.strip().lower()
        C.portal_saml = portal_saml
        C.gateway_saml = gateway_saml
        return '', 201
    else:
        return 'Current configuration of fake GP server configuration:\n{}\n'.format(C)


# Respond to initial prelogin requests
@app.route('/<any("global-protect", "ssl-vpn"):interface>/prelogin.esp', methods=('GET','POST',))
def prelogin(interface):
    ifname = if_path2name[interface]
    demand_saml = getattr(C, ifname + '_saml')
    if demand_saml:
        # The (cookie-based) session isn't shared between OpenConnect and the external browser
        # that does the SAML auth, so we need another way to track that the SAML form gets
        # returned. Use a global variable for now.
        token = '%08x' % randint(0x10000000, 0xffffffff)
        OUTSTANDING_SAML_TOKENS.add((ifname, token))
        saml = '<saml-auth-method>REDIRECT</saml-auth-method><saml-request>{}</saml-request>'.format(
            base64.standard_b64encode(url_for('saml_handler', ifname=ifname, token=token, _external=True).encode()).decode())
    else:
        saml = ''
    session.update(step='%s-prelogin' % ifname)
    return '''
<prelogin-response>
<status>Success</status>
<ccusername/>
<autosubmit>false</autosubmit>
<msg/>
<newmsg/>
<authentication-message>Please login to this fake GP VPN {ifname}</authentication-message>
<username-label>Username</username-label>
<password-label>Password</password-label>
<panos-version>1</panos-version>{saml}
<region>EARTH</region>
</prelogin-response>'''.format(ifname=ifname, saml=saml)


# In a "real" GP VPN with SAML, this lives on a completely different server like subdomain.okta.com
# or login.microsoft.com.
# It will be opened by an external browser or SAML-wrangling script, *not* by OpenConnect.
@app.route('/ANOTHER-HOST/SAML-ENDPOINT')
def saml_handler():
    ifname, token = request.args.get('ifname'), request.args.get('token')

    # Submit to saml_complete endpoint
    # In a "real" GP setup, this would be on a different server which is why we use _external=True
    saml_complete = url_for('saml_complete', _external=True)

    return '''<html><body><p>Please login to this fake GP VPN {ifname} interface via SAML</p>
<form name="saml" method="post" action="{saml_complete}">
<input type="text" name="username" autofocus="1"/><br/>
<input type="password" name="password"/><br/>
<input type="hidden" name="token" value="{token}"/>
<input type="hidden" name="ifname" value="{ifname}"/>
<input type="submit" value="Login"/>
</form></body></html>'''.format(ifname=ifname, saml_complete=saml_complete, token=token)


# This is the "return path" where SAML authentication ends up on real GP servers after
# successfully completing.
# It will be opened by an external browser or SAML-wrangling script, *not* by OpenConnect.
@app.route('/SAML20/SP/ACS', methods=('POST',))
def saml_complete():
    ifname, token = request.form.get('ifname'), request.form.get('token')
    assert ifname in ('portal', 'gateway')

    try:
        OUTSTANDING_SAML_TOKENS.remove((ifname, token))
    except KeyError:
        # Token and/or endpoint were bogus
        abort(401)

    # Build a response containing the magical headers that indicate SAML completion
    saml_headers = {
        'saml-auth-status': 1,
        'saml-username': request.form.get('username'),
        getattr(C, ifname + '_saml'): 'FAKE_username_{username}_password_{password}'.format(**request.form),
    }

    body = '<html><body>Login Successful!</body><!-- {} --></html>'.format(''.join('<{0}>{1}</{0}>'.format(*kv) for kv in saml_headers.items()))
    return body, saml_headers


def challenge_2fa(where, variant):
    # select a random inputStr of 4 hex digits, and randomly return challenge in either XML or Javascript-y or HTML-wrapped Javascript-y form
    inputStr = '%04x' % randint(0x1000, 0xffff)
    session.update(step='%s-2FA' % where, inputStr=inputStr)

    variants = ('xml', 'js', 'html')
    if variant not in variants:
        variant = choice(variants)

    if variant == 'xml':
        return f'<challenge><respmsg>XML 2FA challenge from &apos;{where}&apos; & throw in an illegal unquoted ampersand</respmsg><inputstr>{inputStr}</inputstr></challenge>'
    else:
        # Include literal '\n', JS-escaped ["'\n], and JS-unescaped '\'' in respMsg as a torture test;
        # if wrapping in HTML, additionally add HTML entity escapes of [<>'"&]
        js = ('var respStatus = "Challenge";\n'
              f'''var respMsg = "\\n\\"Javascript\\" 2FA challenge <- \\'{where}'\n===========================";\n'''
              f'thisForm.inputStr.value = "{inputStr}";\n')
        if variant == 'html':
            js = escape(js, quote=True)
            return f'<html><head></head><body>{js}</body></html>'
        else:
            return js


# Respond to portal getconfig request
@app.route('/global-protect/getconfig.esp', methods=('POST',))
def portal_config():
    inputStr = request.form.get('inputStr') or None

    if C.portal_2fa and not inputStr:
        return challenge_2fa('portal', C.portal_2fa)

    okay = False
    if C.portal_saml and request.form.get('user') and request.form.get(C.portal_saml):
        okay = True
    elif request.form.get('user') and request.form.get('passwd') and inputStr == session.get('inputStr'):
        okay = True
    if not okay:
        return 'Invalid username or password', 512

    session.update(step='portal-config', user=request.form.get('user'), passwd=request.form.get('passwd'),
                   # clear SAML result fields to ensure failure if blindly retried on gateway
                   saml_user=None, saml_value=None,
                   # clear inputStr to ensure failure if same form fields are blindly retried on another challenge form:
                   inputStr=None)
    gwlist = ''.join('<entry name="{}:{}"><description>{}</description></entry>'.format(app.config['HOST'], app.config['PORT'], gw)
                     for gw in C.gateways)
    if C.portal_cookie:
        val = session[C.portal_cookie] = 'portal-cookie-%d' % randint(1, 10)
        pc = '<{0}>{1}</{0}>'.format(C.portal_cookie, val)
    else:
        pc = ''

    return '''<?xml version="1.0" encoding="UTF-8" ?>
    <policy><version> 6.7.8-9 </version><gateways><external><list>{}</list></external></gateways>
    <hip-collection><hip-report-interval>600</hip-report-interval></hip-collection>
    {}</policy>'''.format(gwlist, pc)


# Respond to gateway login request
@app.route('/ssl-vpn/login.esp', methods=('POST',))
def gateway_login():
    inputStr = request.form.get('inputStr') or None

    if C.portal_cookie and request.form.get(C.portal_cookie) == session.get(C.portal_cookie):
        # a correct portal_cookie explicitly allows us to bypass other gateway login forms
        pass
    elif C.gw_2fa and not inputStr:
        return challenge_2fa('gateway', C.gw_2fa)
    else:
        okay = False
        if C.gateway_saml and request.form.get('user') and request.form.get(C.gateway_saml):
            okay = True
        elif request.form.get('user') and request.form.get('passwd') and inputStr == session.get('inputStr'):
            okay = True
        if not okay:
            return 'Invalid username or password', 512
    session.update(step='gateway-login', user=request.form.get('user'), passwd=request.form.get('passwd'),
                   # clear inputStr to ensure failure if same form fields are blindly retried on another challenge form:
                   inputStr=None)

    for k, v in (('jnlpReady', 'jnlpReady'), ('ok', 'Login'), ('direct', 'yes'), ('clientVer', '4100'), ('prot', 'https:')):
        if request.form.get(k) != v:
            abort(500)
    for k in ('clientos', 'os-version', 'server', 'computer'):
        if not request.form.get(k):
            abort(500)

    portal = 'Portal%d' % randint(1, 10)
    auth = 'Auth%d' % randint(1, 10)
    domain = 'Domain%d' % randint(1, 10)
    preferred_ip = request.form.get('preferred-ip') or '192.168.%d.%d' % (randint(2, 254), randint(2, 254))
    if request.form.get('ipv6-support') == 'yes':
        preferred_ipv6 = request.form.get('preferred-ipv6') or 'fd00::%x' % randint(0x1000, 0xffff)
    else:
        preferred_ipv6 = None
    session.update(preferred_ip=preferred_ip, portal=portal, auth=auth, domain=domain, computer=request.form.get('computer'),
                   ipv6_support=request.form.get('ipv6-support'), preferred_ipv6=preferred_ipv6)
    session.setdefault('portal-prelogonuserauthcookie', '')
    session.setdefault('portal-userauthcookie', '')
    session['authcookie'] = cookify(dict(session)).decode()

    return '''<?xml version="1.0" encoding="utf-8"?> <jnlp> <application-desc>
        <argument>(null)</argument>
            <argument>{authcookie}</argument>
            <argument>PersistentCookie</argument>
            <argument>{portal}</argument>
            <argument>{user}</argument>
            <argument>TestAuth</argument>
            <argument>vsys1</argument>
            <argument>{domain}</argument>
            <argument>(null)</argument>
            <argument/>
            <argument></argument>
            <argument></argument>
            <argument>tunnel</argument>
            <argument>-1</argument>
            <argument>4100</argument>
            <argument>{preferred_ip}</argument>
            <argument>{portal-userauthcookie}</argument>
            <argument>{portal-prelogonuserauthcookie}</argument>
            <argument>{ipv6}</argument>
            </application-desc></jnlp>'''.format(ipv6=preferred_ipv6 or '', **session)


# Respond to gateway getconfig request
@app.route('/ssl-vpn/getconfig.esp', methods=('POST',))
@check_form_against_session('user', 'portal', 'domain', 'authcookie', 'preferred_ip', 'preferred_ipv6', 'ipv6_support', on_failure="errors getting SSL/VPN config")
def getconfig():
    session.update(step='gateway-config')
    addrs = '<ip-address>{}</ip-address>'.format(session['preferred_ip'])
    if session['ipv6_support'] == 'yes':
        addrs += '<ip-address-v6>{}</ip-address-v6>'.format(session['preferred_ipv6'])
    return '''<response>{}<ssl-tunnel-url>/ssl-tunnel-connect.sslvpn</ssl-tunnel-url></response>'''.format(addrs)


# Respond to gateway hipreportcheck request
@app.route('/ssl-vpn/hipreportcheck.esp', methods=('POST',))
@check_form_against_session('user', 'portal', 'domain', 'authcookie', 'computer')
def hipcheck():
    session.update(step='gateway-config')
    return '''<response><hip-report-needed>no</hip-report-needed></response>'''


# Respond to faux-CONNECT GET-tunnel with 502
# (what the real GP server responds with when it doesn't like the cookie, intended
# to trigger "cookie rejected" error in OpenConnect)
@app.route('/ssl-tunnel-connect.sslvpn')
# Can't use because OpenConnect doesn't send headers here
# @check_form_against_session('user', 'authcookie', use_query=True)
def tunnel():
    assert 'user' in request.args and 'authcookie' in request.args
    session.update(step='GET-tunnel')
    abort(502)


# Respond to 'GET /ssl-vpn/logout.esp' by clearing session and MRHSession
@app.route('/ssl-vpn/logout.esp')
# XX: real server really requires all these fields; see auth-globalprotect.c
@check_form_against_session('authcookie', 'portal', 'user', 'computer')
def logout():
    return '<response status="success"/>'


app.run(host=app.config['HOST'], port=app.config['PORT'], debug=True, ssl_context=context)
