#!/usr/bin/env python3
#
# Copyright © 2021 Joachim Kuebart <joachim.kuebart@gmail.com>
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

from flask import (
    Flask, make_response, redirect, render_template_string, request,
    url_for
)
import re
import ssl
import sys

host, port, *cert_and_maybe_keyfile = sys.argv[1:]

context = ssl.SSLContext()
context.load_cert_chain(*cert_and_maybe_keyfile)

app = Flask(__name__)


@app.route("/")
def root():
    # Step 0. Step 11.
    return redirect(url_for("welcome"))


@app.route("/dana-na/auth/url_default/welcome.cgi")
def welcome():
    if request.args.get("p") != "preauth":
        # Step 1. Step 12.
        return redirect(url_for("login"))

    if request.cookies.get("DSPREAUTH") != "success":
        # Step 14: set DSPREAUTH.
        resp = make_response("Waiting for host checker…")
        resp.set_cookie("DSPREAUTH", "hostchecker")
        return resp

    # Step 15.
    return redirect(url_for("login", loginmode="mode_postAuth"))


@app.route("/dana-na/auth/url_default/login.cgi")
def login():
    if request.cookies.get("DSASSERTREF") != "assert_ref":
        # Step 2.
        return redirect(url_for("ls"))

    if request.args.get("loginmode") != "mode_postAuth":
        # Step 13.
        return redirect(url_for("welcome", p="preauth"))

    # Step 16: set DSID.
    resp = redirect(url_for("starter0"))
    resp.set_cookie("DSID", "dsid")
    return resp


@app.route("/adfs/ls/", methods=["GET", "POST"])
def ls():
    if request.cookies.get("MSISAuth") != "success":
        if (
            request.method == "GET" or
            request.form.get("UserName") != "test@example.com" or
            request.form.get("Password") != "test"
        ):
            # Step 3: user/password form.
            return render_template_string("""<!doctype html>
                <form action="{{ url_for("ls") }}"
                      id="loginForm"
                      method="post">
                    <input id="userNameInput" name="UserName" type="email">
                    <input id="passwordInput" name="Password" type="password">
                    <input id="KmsiInput" name="Kmsi" type="checkbox">
                    <input id="optionForms"
                           name="AuthMethod"
                           type="hidden"
                           value="FormsAuthentication">
                </form>
                <form action="{{ url_for("ls") }}" id="options" method="post">
                    <input id="optionSelection"
                           name="AuthMethod"
                           type="hidden">
                </form>""")

        # Step 4: username/password success.
        resp = redirect(url_for("ls"))
        resp.set_cookie("MSISAuth", "success")
        return resp

    if request.cookies.get("MSISAuth1") != "success":
        if (
            "VerificationCode" not in request.form or
            not re.match("^\\d{6}$", request.form["VerificationCode"])
        ):
            # Step 5. Step 6: TOTP form.
            return render_template_string("""<!doctype html>
                <form id="loginForm" method="post">
                    <input id="autheMethod"
                           name="AuthMethod"
                           type="hidden"
                           value="AzureMfaAuthentication">
                    <input id="context" name="Context" type="hidden">
                    <input id="__EVENTTARGET"
                           name="__EVENTTARGET"
                           type="hidden">
                    {% if request.method == "POST" %}
                        <input id="verificationCodeInput"
                               name="VerificationCode"
                               type="text">
                        <input id="signInButton"
                               name="SignIn"
                               type="submit"
                               value="Sign in">
                    {% endif %}
                </form>
                <form action="{{ url_for("ls") }}" id="options" method="post">
                    <input id="optionSelection"
                           name="AuthMethod"
                           type="hidden">
                </form>""")

        # Step 7: TOTP success.
        resp = redirect(url_for("ls"))
        resp.set_cookie("MSISAuth1", "success")
        return resp

    # Step 8.
    return render_template_string("""<!doctype html>
        <form action="{{ url_for("saml_consumer0") }}"
              method="post"
              name="hiddenform">
            <input name="SAMLResponse" type="hidden">
            <input name="RelayState" type="hidden">
            <input type="submit" value="Submit">
        </form>""")


@app.route("/data-na/auth/saml-consumer0.cgi", methods=["POST"])
def saml_consumer0():
    # Step 9: in reality, this is hosted on a different domain than the
    # next step.
    return render_template_string("""<!doctype html>
        <form action="{{ url_for("saml_consumer") }}"
              id="formSAMLSSO"
              method="post">
            <input id="RelayState" name="RelayState" type="hidden">
            <input id="SAMLResponse" name="SAMLResponse" type="hidden">
            <input id="input_saml-response-post_1"
                   type="submit"
                   value="Continue">
        </form>""")


@app.route("/data-na/auth/saml-consumer.cgi", methods=["POST"])
def saml_consumer():
    # Step 10.
    resp = redirect(url_for("root"))
    resp.set_cookie("DSASSERTREF", "assert_ref")
    return resp


@app.route("/dana/home/starter0.cgi")
def starter0():
    # Need to provide a form to make the parser happy.
    return "<form></form>The DSID is in your cookie jar."


app.run(host=host, port=int(port), ssl_context=context)
