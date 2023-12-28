/*
 * OpenConnect (SSL + DTLS) VPN client
 *
 * Copyright © 2022 David Woodhouse <dwmw2@infradead.org>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * version 2.1, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 */

#include <stdlib.h>
#include <stdio.h>

#include <gnutls/system-keys.h>

int main(void)
{
	gnutls_system_key_iter_t iter = NULL;
	char *cert, *key, *label;
	gnutls_datum_t der = { };
	int err;

	while ((err = gnutls_system_key_iter_get_info(&iter, GNUTLS_CRT_X509,
						      &cert, &key, &label, &der, 0)) >= 0) {
		/* Skip anything without a key */
		if (cert && key) {
			printf("Label: %s\nCert URI: %s\nKey URI: %s\n", label, cert, key);
			gnutls_x509_crt_t crt = NULL;
			gnutls_datum_t buf = { };

			if (!gnutls_x509_crt_init(&crt) &&
			    !gnutls_x509_crt_import(crt, &der, GNUTLS_X509_FMT_DER) &&
			    !gnutls_x509_crt_print(crt, GNUTLS_CRT_PRINT_ONELINE, &buf))
				printf("Cert info: %s\n", buf.data);

			gnutls_free(buf.data);
			gnutls_x509_crt_deinit(crt);
			printf("\n");
		}
		gnutls_free(der.data);
		der.data = NULL;
		gnutls_free(label);
		gnutls_free(key);
		gnutls_free(cert);
	}

	if (err == GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE)
		err = 0;
	else if (err == GNUTLS_E_UNIMPLEMENTED_FEATURE)
		fprintf(stderr, "GnuTLS does not support a concept of system keys on this platform.\n");
	else if (err < 0)
		fprintf(stderr, "Error listing keys: %s\n", gnutls_strerror(err));

	gnutls_system_key_iter_deinit(iter);

	return !!err;
}
