#!/usr/bin/python3

from sys import stderr
from urllib.parse import urlparse
import http.client as httplib
import requests
import argparse
import getpass
from datetime import datetime
from shlex import quote

p = argparse.ArgumentParser()
p.add_argument('-v', '--verbose', default=0, action='count')
p.add_argument('endpoint', help='F5 server (or complete URL, e.g. https://f5.vpn.com/my.policy)')
p.add_argument('extra', nargs='*', help='Extra field to pass to include in the login query string (e.g. "foo=bar")')
g = p.add_argument_group('Login credentials')
g.add_argument('-u', '--username', help='Username (will prompt if unspecified)')
g.add_argument('-p', '--password', help='Password (will prompt if unspecified)')
g.add_argument('-c', '--cert', help='PEM file containing client certificate (and optionally private key)')
g.add_argument('--key', help='PEM file containing client private key (if not included in same file as certificate)')
p.add_argument('--no-verify', dest='verify', action='store_false', default=True, help='Ignore invalid server certificate')
args = p.parse_args()

if args.verbose > 1:
    httplib.HTTPConnection.debuglevel = 1

extra = dict(x.split('=', 1) for x in args.extra)
endpoint = urlparse(('https://' if '//' not in args.endpoint else '') + args.endpoint, 'https:')

if args.cert and args.key:
    cert = (args.cert, args.key)
elif args.cert:
    cert = (args.cert, None)
elif args.key:
    p.error('--key specified without --cert')
else:
    cert = None

s = requests.Session()
s.cert = cert
s.verify = args.verify
#s.headers['User-Agent'] = 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:75.0) Gecko/20100101 Firefox/75.0'

print("Initial GET / to populate LastMRH_Session and MRHSession cookies...", file=stderr)
res = s.get(endpoint.geturl(), allow_redirects=False)
assert any(c.value for c in s.cookies if c.name == 'MRHSession') and any(c.value for c in s.cookies if c.name == 'LastMRH_Session')
#print("GET /my.policy to update MRHSession cookie...", file=stderr)
#res = s.get(endpoint._replace(path='/my.policy').geturl(), allow_redirects=False, headers={'Referer': res.url})
#print("GET /vdesk/timeoutagent-i.php to update TIN cookie (probably unnecessary).")
#res = s.get(endpoint._replace(path='/vdesk/timeoutagent-i.php').geturl(), allow_redirects=False)

# Send login credentials
if args.username is None:
    args.username = input('Username: ')
if args.password is None:
    args.password = getpass.getpass('Password: ')
data = dict(username=args.username, password=args.password,
            **extra)
print("POST /my.policy to submit login credentials...", file=stderr)
res = s.post(endpoint._replace(path='/my.policy').geturl(), data=data, headers={'Referer': res.url})
res.raise_for_status()

st_cookie = next((c for c in s.cookies if c.name == 'F5_ST'), None)
if not st_cookie:
    print("No F5_ST cookie in response (ended at %s) -- bad credentials?" % res.url, file=stderr)
else:
    # Parse "session timeout" cookie (https://support.f5.com/csp/article/K15387) which looks like '1z1z1z1612808487z604800'
    fields = st_cookie.value.split('z')
    authat, expat = datetime.fromtimestamp(int(fields[3])), datetime.fromtimestamp(int(fields[3]) + int(fields[4]))
    print("F5_ST cookie %r valid from %s - %s" % (st_cookie.value, authat, expat), file=stderr)


# Build openconnect --cookie argument from the result:
url = urlparse(res.url)
cookie = next((c.value for c in s.cookies if c.name == 'MRHSession'), None)
if cookie and url.path.startswith('/vdesk/'):
    if args.verbose:
        if cert:
            cert_and_key = ' \\\n        ' + ' '.join('%s "%s"' % (opt, quote(fn)) for opt, fn in zip(('-c', '-k'), cert) if fn)
        else:
            cert_and_key = ''

        print('''
Extracted connection cookie. Use this to connect:

    echo %s | openconnect --protocol=f5%s --cookie-on-stdin %s

''' % (quote(cookie), cert_and_key, quote(endpoint.netloc)), file=stderr)

    varvals = {
        'HOST': quote(url.netloc),
        'COOKIE': quote(cookie),
    }
    print('\n'.join('%s=%s' % pair for pair in varvals.items()))

# Just print the result
else:
    if args.verbose:
        print(res.headers, file=stderr)
    print(res.text)
