# OpenConnect

OpenConnect is an SSL VPN client initially created to support [Cisco's AnyConnect SSL VPN](https://www.cisco.com/site/us/en/products/security/secure-client/index.html).

It has since been ported to support the Juniper SSL VPN (which is now known as [Pulse Connect Secure](https://www.ivanti.com/products/connect-secure-vpn)),
the [Palo Alto Networks GlobalProtect SSL VPN](https://www.paloaltonetworks.com/features/vpn)
the [F5 Big-IP SSL VPN](https://www.f5.com/products/big-ip-services),
and the [Fortinet FortiGate SSL VPN](https://www.fortinet.com/products/vpn).</p>

An openconnect VPN server (ocserv), which implements an improved version of the Cisco AnyConnect protocol, has also been written.
You can find it on Gitlab at [https://gitlab.com/openconnect/ocserv](https://gitlab.com/openconnect/ocserv).

If you're looking for the standard `vpnc-script`, which is invoked by OpenConnect for routing and DNS setup,
you can find it on Gitlab at [https://gitlab.com/openconnect/vpnc-scripts](https://gitlab.com/openconnect/vpnc-scripts).

## Licence

OpenConnect is released under the [GNU Lesser Public License, version 2.1](https://www.infradead.org/openconnect/licence.html).

## Documentation

Documentation for OpenConnect is built from the `www/` directory in this repository, and lives in rendered form at [https://www.infradead.org/openconnect](https://www.infradead.org/openconnect).

Commonly-sought documentation:

* [Manual](https://www.infradead.org/openconnect/manual.html)
* [Getting Started / Building](https://www.infradead.org/openconnect/building.html) (includes build instructions)
* [Packages](https://www.infradead.org/openconnect/packages.html)
   (including latest development build of the CLI [for 64-bit Windows](https://gitlab.com/openconnect/openconnect/-/jobs/artifacts/master/raw/openconnect-installer-MinGW64-GnuTLS.exe?job=MinGW64/GnuTLS),
   and [for 32-bit Windows](https://gitlab.com/openconnect/openconnect/-/jobs/artifacts/master/raw/openconnect-installer-MinGW32-GnuTLS.exe?job=MinGW32/GnuTLS))
* [Contribute](https://www.infradead.org/openconnect/contribute.html)
* [Mailing list / Help](https://www.infradead.org/openconnect/mail.html)
* [GUIs / Front Ends](https://www.infradead.org/openconnect/gui.html)
* [VPN Server / ocserv](https://www.infradead.org/ocserv/)
* [Protocol-specific details](https://www.infradead.org/openconnect/protocols.html)
