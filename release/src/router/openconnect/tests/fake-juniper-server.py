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
# This program emulates the authentication-phase behavior of a Juniper
# server enough to test OpenConnect's authentication behavior against it.
########################################

import sys
import ssl
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


def require_DSID(fn):
    @wraps(fn)
    def wrapped(*args, **kwargs):
        if not request.cookies.get('DSID'):
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
#   realms: Comma-separated list of realms to offer (frmLogin will contain a dropdown for this)
#   roles: Comma-separated list of roles to offer (frmSelectRoles will contain links for each)
#     --authgroup can fill EITHER realm OR role; we've never seen a VPN that uses both
#   confirm: If True (default False), frmConfirmation will be added as the final step in auth
#   token_form: If specified, name of token/2FA form to include
#     (frmLogin, frmTotpToken, frmDefender, or frmNextToken)
@dataclass
class TestConfiguration:
    realms: list = ()
    roles: list = ()
    confirm: bool = False
    token_form: str = None
C = TestConfiguration()


@app.route('/CONFIGURE', methods=('POST', 'GET'))
def configure():
    global C
    if request.method == 'POST':
        C = TestConfiguration(
            realms=request.form['realms'].split(',') if 'realms' in request.form else (),
            roles=request.form['roles'].split(',') if 'roles' in request.form else (),
            confirm=bool(request.form.get('confirm')),
            token_form=request.form.get('token_form'))
        return '', 201
    else:
        return 'Current configuration of fake Juniper server:\n{}\n'.format(C)


@app.route('/')
def root():
    # We don't support the Junos/Pulse protocol (which starts with this request)
    if request.headers.get('Upgrade') == 'IF-T/TLS 1.0' and request.headers.get('Content-Type') == 'EAP':
        return abort(501)

    session.update(step='initial-GET')
    # print(session)
    return redirect(url_for('frmLogin'))


# frmLogin
@app.route('/dana-na/auth/url_default/welcome.cgi')
def frmLogin():
    global C
    session.update(step='GET-frmLogin')
    sel = token = ''
    if C.realms:
        sel = '<select name="realm">%s</select>' % ''.join(
            '<option value="%d">%s</option>' % nv for nv in enumerate(C.realms))
    if C.token_form == 'frmLogin':
        token = '<input type="password" name="token_as_second_password"/>'

    return '''
<html><body><form name="frmLogin" method="post" action="%s">
<input type="text" name="username"/>
<input type="password" name="password"/>
%s<input type="submit" value="Sign In" name="btnSubmit"/>
%s</form></body></html>''' % (url_for('frmLogin_post'), token, sel)


# frmLogin POST-response
# This either yields a successful DSID cookie, or redirects to a confirmation page,
# depending on session['confirm']
@app.route('/dana-na/auth/url_default/login.cgi', methods=['POST'])
def frmLogin_post():
    global C
    if C.realms:
        assert 0 <= int(request.form.get('realm', -1)) < len(C.realms)
    session.update(step='POST-login', username=request.form.get('username'),
                   password=request.form.get('password'),
                   realm=request.form.get('realm'))
    # print(session)

    need_confirm = need_token = False
    got_confirm = got_token = None
    if C.confirm:
        need_confirm = request.form.get('btnContinue') is None
        got_confirm = not need_confirm
    if C.token_form:
        need_token = request.form.get('btnAction') is None and request.form.get('totpactionEnter') is None and request.form.get('token_as_second_password') is None
        got_token = not need_token
    session.update(got_token=got_token, got_confirm=got_confirm)

    if need_token and not got_confirm:
        return redirect(url_for('frm2FA'))
    elif need_confirm:
        return redirect(url_for('frmConfirmation'))
    elif C.roles:
        return redirect(url_for('frmSelectRoles'))
    else:
        resp = redirect(url_for('webtop'))
        resp.set_cookie('DSID', cookify(dict(session)))
        return resp


# frmSelectRoles
# This is some insane post-login realm-ish select-y thing
@app.route('/dana-na/auth/url_default/select_role.cgi')
def frmSelectRoles():
    global C
    session.update(step='GET-frmSelectRoles')
    dest = url_for('frmSelectRoles_AFTER')
    roles = '\n'.join('<tr><td><a href="%s?role=%d">%s</a></td></tr>' % (dest, nn, role) for (nn, role) in enumerate(C.roles))
    return '''
<html><body><form name="frmSelectRoles">
<table id="TABLE_SelectRole_1">
<tr><td>You have access to the following roles:</td></tr>
%s
<tr><td>Each role allows you to access certain resources.  Click on the role you want to join for this session.  Please contact your administrator if you need help choosing a role.</td></tr>
</table>
</form></body></form>''' % roles


# Note the URL is shared with the frmLogin POST URL... so weird
@app.route('/dana-na/auth/url_default/login.cgi', methods=['GET'])
def frmSelectRoles_AFTER():
    global C
    assert C.roles
    assert 0 <= int(request.args.get('role', -1)) < len(C.roles)
    session.update(step='AFTER-frmSelectRoles', role=request.form.get('role'))
    resp = redirect(url_for('webtop'))
    resp.set_cookie('DSID', cookify(dict(session)))
    return resp


# 2FA forms (frmDefender, frmNextToken, or frmTotpToken)
# This redirects back to frmLogin_POST
@app.route('/dana-na/auth/url_default/token.cgi')
def frm2FA():
    global C
    submit_button = ('totpactionEnter' if C.token_form == 'frmTotpToken' else 'btnAction')
    session.update(step='GET-' + C.token_form)
    return '''
<html><body><form name="%s" method="post" action="%s">
Enter your 2FA token code.
<input type="hidden" name="username" value="%s"/>
<input type="password" name="token_code"/>
<input type="hidden" name="realm" value="%s"/>
<input type="submit" name="%s" value="Sign In"/>
</form></body></html>''' % (
    C.token_form,
    url_for('frmLogin_post'), session.get('username'), session.get('realm'),
    submit_button
)


# frmConfirmation
# This redirects back to frmLogin_POST
@app.route('/dana-na/auth/url_default/confirm.cgi')
def frmConfirmation():
    session.update(step='GET-frmConfirm')
    return '''
<html><body><form name="frmConfirmation" method="post" action="%s">
Confirm your login for whatever reason.
<input type="hidden" name="username" value="%s"/>
<input type="hidden" name="password" value="%s"/>
<input type="hidden" name="realm" value="%s"/>
<input type="submit" name="btnContinue" value="Confirm Login"/>
</form></body></html>''' % (
    url_for('frmLogin_post'), session.get('username'), session.get('password'),
    session.get('realm'))


# stand-in for the "webtop" UI if logged in through a browser
@app.route('/dana/home/starter0.cgi')
def webtop():
    session.update(step='POST-login-webtop')
    # print(session)

    return 'some junk HTML webtop'


# respond to faux-CONNECT 'POST /dana/na?prot=1&svc=4' with 401
@app.route('/dana/js', methods=['POST'])
@require_DSID
def tunnel_post():
    session.update(step='POST-tunnel')
    assert request.args.get('prot') == '1' and request.args.get('svc') == '4'
    assert request.headers['Connection'].lower().strip() == 'close'
    abort(401)


# Respond to 'GET /dana-na/auth/logout.cgi' by clearing session and DSID
@app.route('/dana-na/auth/logout.cgi')
@require_DSID
def logout():
    session.clear()
    resp = make_response('successful logout')
    resp.set_cookie('DSID', '')
    return resp


app.run(host=app.config['HOST'], port=app.config['PORT'], debug=app.config['DEBUG'],
        ssl_context=context, use_debugger=False)
