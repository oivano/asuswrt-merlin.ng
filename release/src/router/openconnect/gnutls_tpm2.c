/*
 * OpenConnect (SSL + DTLS) VPN client
 *
 * Copyright © 2018 David Woodhouse.
 *
 * Author: David Woodhouse <dwmw2@infradead.org>
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

#include <config.h>

#include "openconnect-internal.h"

#include "gnutls.h"

#include <gnutls/gnutls.h>

#include <errno.h>
#include <string.h>

#ifdef HAVE_TSS2

#include <libtasn1.h>

/*
 * TPMKey ::= SEQUENCE {
 *	type		OBJECT IDENTIFIER,
 *	emptyAuth	[0] EXPLICIT BOOLEAN OPTIONAL,
 *	parent		INTEGER,
 *	pubkey		OCTET STRING,
 *	privkey		OCTET STRING
 * }
 */
const asn1_static_node tpmkey_asn1_tab[] = {
  { "TPMKey", 536875024, NULL },
  { NULL, 1073741836, NULL },
  { "TPMKey", 536870917, NULL },
  { "type", 1073741836, NULL },
  { "emptyAuth", 1610637316, NULL },
  { NULL, 2056, "0"},
  { "parent", 1073741827, NULL },
  { "pubkey", 1073741831, NULL },
  { "privkey", 7, NULL },
  { NULL, 0, NULL }
};

const asn1_static_node tpmkey_asn1_tab_old[] = {
  { "TPMKey", 536875024, NULL },
  { NULL, 1073741836, NULL },
  { "TPMKey", 536870917, NULL },
  { "type", 1073741836, NULL },
  { "emptyAuth", 1610637316, NULL },
  { NULL, 2056, "0"},
  { "parent", 1610637315, NULL },
  { NULL, 2056, "1"},
  { "pubkey", 1610637319, NULL },
  { NULL, 2056, "2"},
  { "privkey", 7, NULL },
  { NULL, 0, NULL }
};

static const char OID_legacy_loadableKey[] = "2.23.133.10.2";
static const char OID_loadableKey[] =        "2.23.133.10.1.3";

#if GNUTLS_VERSION_NUMBER < 0x030600
static int tpm2_rsa_sign_fn(gnutls_privkey_t key, void *_certinfo,
			    const gnutls_datum_t *data, gnutls_datum_t *sig)
{
	return tpm2_rsa_sign_hash_fn(key, GNUTLS_SIGN_UNKNOWN, _certinfo, 0, data, sig);
}


static int tpm2_ec_sign_fn(gnutls_privkey_t key, void *_certinfo,
			   const gnutls_datum_t *data, gnutls_datum_t *sig)
{
	struct cert_info *certinfo = _certinfo;
	struct openconnect_info *vpninfo = certinfo->vpninfo;
	gnutls_sign_algorithm_t algo;

	switch (data->size) {
	case SHA1_SIZE:   algo = GNUTLS_SIGN_ECDSA_SHA1; break;
	case SHA256_SIZE: algo = GNUTLS_SIGN_ECDSA_SHA256; break;
	case SHA384_SIZE: algo = GNUTLS_SIGN_ECDSA_SHA384; break;
	case SHA512_SIZE: algo = GNUTLS_SIGN_ECDSA_SHA512; break;
	default:
		vpn_progress(vpninfo, PRG_ERR,
			     _("Unknown TPM2 EC digest size %d\n"),
			     data->size);
		return GNUTLS_E_PK_SIGN_FAILED;
	}

	return tpm2_ec_sign_hash_fn(key, algo, certinfo, 0, data, sig);
}
#endif

#if GNUTLS_VERSION_NUMBER >= 0x030600
static int rsa_key_info(gnutls_privkey_t key, unsigned int flags, void *_certinfo)
{
	struct cert_info *certinfo = _certinfo;
	struct openconnect_info *vpninfo = certinfo->vpninfo;

	if (flags & GNUTLS_PRIVKEY_INFO_PK_ALGO)
		return GNUTLS_PK_RSA;

	if (flags & GNUTLS_PRIVKEY_INFO_SIGN_ALGO)
		return GNUTLS_SIGN_RSA_RAW;

	int bits = tpm2_rsa_key_bits(vpninfo, certinfo);

	if (flags & GNUTLS_PRIVKEY_INFO_PK_ALGO_BITS)
		return bits;

	if (flags & GNUTLS_PRIVKEY_INFO_HAVE_SIGN_ALGO) {
		gnutls_sign_algorithm_t algo = GNUTLS_FLAGS_TO_SIGN_ALGO(flags);
		switch (algo) {
		case GNUTLS_SIGN_RSA_RAW:
		case GNUTLS_SIGN_RSA_SHA1:
		case GNUTLS_SIGN_RSA_SHA256:
		case GNUTLS_SIGN_RSA_SHA384:
		case GNUTLS_SIGN_RSA_SHA512:
			return 1;

		/* Only support RSA-PSS for a given hash if the key is large
		 * enough, since RFC8446 mandates that the salt length MUST
		 * equal the digest output length. So we need 2N + 2 bytes. */
		case GNUTLS_SIGN_RSA_PSS_SHA256:
		case GNUTLS_SIGN_RSA_PSS_RSAE_SHA256:
			if (bits >= (SHA256_SIZE * 16) + 16)
				return 1;
			/* Fall through */
		case GNUTLS_SIGN_RSA_PSS_SHA384:
		case GNUTLS_SIGN_RSA_PSS_RSAE_SHA384:
			if (bits >= (SHA384_SIZE * 16) + 16)
				return 1;
			/* Fall through */
		case GNUTLS_SIGN_RSA_PSS_SHA512:
		case GNUTLS_SIGN_RSA_PSS_RSAE_SHA512:
			if (bits >= (SHA512_SIZE * 16) + 16)
				return 1;
			/* Fall through */
		default:
			vpn_progress(vpninfo, PRG_DEBUG,
				     _("Not supporting EC sign algo %s\n"),
				     gnutls_sign_get_name(algo));
			return 0;
		}
	}

	return -1;
}
#endif

#if GNUTLS_VERSION_NUMBER >= 0x030400
static int ec_key_info(gnutls_privkey_t key, unsigned int flags, void *_certinfo)
{
	if (flags & GNUTLS_PRIVKEY_INFO_PK_ALGO)
		return GNUTLS_PK_EC;

#ifdef GNUTLS_PRIVKEY_INFO_HAVE_SIGN_ALGO
	if (flags & GNUTLS_PRIVKEY_INFO_HAVE_SIGN_ALGO) {
		struct cert_info *certinfo = _certinfo;
		struct openconnect_info *vpninfo = certinfo->vpninfo;

		uint16_t tpm2_curve = tpm2_key_curve(vpninfo, certinfo);
		gnutls_sign_algorithm_t algo = GNUTLS_FLAGS_TO_SIGN_ALGO(flags);

		switch (algo) {
		case GNUTLS_SIGN_ECDSA_SHA1:
		case GNUTLS_SIGN_ECDSA_SHA256:
			return 1;

		case GNUTLS_SIGN_ECDSA_SECP256R1_SHA256:
			return tpm2_curve == 0x0003; /* TPM2_ECC_NIST_P256 */

		case GNUTLS_SIGN_ECDSA_SECP384R1_SHA384:
			return tpm2_curve == 0x0004; /* TPM2_ECC_NIST_P384 */

		case GNUTLS_SIGN_ECDSA_SECP521R1_SHA512:
			return tpm2_curve == 0x0005; /* TPM2_ECC_NIST_P521 */

		default:
			vpn_progress(vpninfo, PRG_DEBUG,
				     _("Not supporting EC sign algo %s\n"),
				     gnutls_sign_get_name(algo));
			return 0;
		}
	}
#endif

	if (flags & GNUTLS_PRIVKEY_INFO_SIGN_ALGO)
		return GNUTLS_SIGN_ECDSA_SHA256;

	return -1;
}
#endif

static int decode_data(asn1_node n, gnutls_datum_t *r)
{
	asn1_data_node_st d;
	int len, lenlen;

	if (!n)
		return -EINVAL;

	if (asn1_read_node_value(n, &d) != ASN1_SUCCESS)
		return -EINVAL;

	len = asn1_get_length_der(d.value, d.value_len, &lenlen);
	if (len < 0)
		return -EINVAL;

	r->data = (unsigned char *)d.value + lenlen;
	r->size = len;

	return 0;
}

int load_tpm2_key(struct openconnect_info *vpninfo, struct cert_info *certinfo,
		  gnutls_datum_t *fdata, gnutls_privkey_t *pkey, gnutls_datum_t *pkey_sig)
{
	gnutls_datum_t asn1, pubdata, privdata;
	asn1_node tpmkey_def = NULL, tpmkey = NULL;
	const char *oid = NULL;
	char value_buf[16];
	int value_buflen;
	int emptyauth = 0;
	unsigned int parent;
	int err, ret = -EINVAL;
	const asn1_static_node *asn1tab;

	err = gnutls_pem_base64_decode_alloc("TSS2 PRIVATE KEY", fdata, &asn1);
	if (!err) {
		asn1tab = tpmkey_asn1_tab;
		oid = OID_loadableKey;
	} else {
		if (gnutls_pem_base64_decode_alloc("TSS2 KEY BLOB", fdata, &asn1)) {
			/* Report the first error */
			vpn_progress(vpninfo, PRG_ERR,
				     _("Error decoding TSS2 key blob: %s\n"),
				     gnutls_strerror(err));
			return -EINVAL;
		}
		asn1tab = tpmkey_asn1_tab_old;
		oid = OID_legacy_loadableKey;
	}
	err = asn1_array2tree(asn1tab, &tpmkey_def, NULL);
	if (err != ASN1_SUCCESS) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Failed to create ASN.1 type for TPM2: %s\n"),
			     asn1_strerror(err));
		goto out_asn1;
	}

	asn1_create_element(tpmkey_def, "TPMKey.TPMKey", &tpmkey);
	err = asn1_der_decoding(&tpmkey, asn1.data, asn1.size, NULL);
	if (err != ASN1_SUCCESS) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Failed to decode TPM2 key ASN.1: %s\n"),
			     asn1_strerror(err));
		goto out_tpmkey;
	}

	value_buflen = sizeof(value_buf);
	if (asn1_read_value(tpmkey, "type", value_buf, &value_buflen)) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Failed to parse TPM2 key type OID: %s\n"),
			     asn1_strerror(err));
		goto out_tpmkey;
	}
	if (strncmp(value_buf, oid, value_buflen)) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("TPM2 key has unknown type OID %s not %s\n"),
			     value_buf, oid);
		goto out_tpmkey;
	}

	value_buflen = sizeof(value_buf);
	if (!asn1_read_value(tpmkey, "emptyAuth", value_buf, &value_buflen) &&
	    !strcmp(value_buf, "TRUE"))
		emptyauth = 1;

	memset(value_buf, 0, 5);
	value_buflen = 5;
	err = asn1_read_value(tpmkey, "parent", value_buf, &value_buflen);
	if (err == ASN1_ELEMENT_NOT_FOUND)
		parent = 0x40000001; // RH_OWNER
	else if (err != ASN1_SUCCESS) {
	badparent:
		vpn_progress(vpninfo, PRG_ERR,
			     _("Failed to parse TPM2 key parent: %s\n"),
			     asn1_strerror(err));
		goto out_tpmkey;
	} else {
		int i = 0;
		parent = 0;

		if (value_buflen == 5) {
			if (value_buf[0])
				goto badparent;
			/* Skip the leading zero */
			i++;
		}
		for ( ; i < value_buflen; i++) {
			parent <<= 8;
			parent |= value_buf[i];
		}
	}

	if (decode_data(asn1_find_node(tpmkey, "pubkey"), &pubdata) < 0) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Failed to parse TPM2 pubkey element\n"));
		goto out_tpmkey;
	}
	if (decode_data(asn1_find_node(tpmkey, "privkey"), &privdata) < 0) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Failed to parse TPM2 privkey element\n"));
		goto out_tpmkey;
	}

	vpn_progress(vpninfo, PRG_DEBUG,
		     _("Parsed TPM2 key with parent %x, emptyauth %d\n"),
		     parent, emptyauth);

	/* Now we've extracted what we need from the ASN.1, invoke the
	 * actual TPM2 code (whichever implementation we end up with */
	ret = install_tpm2_key(vpninfo, certinfo, pkey, pkey_sig, parent, emptyauth,
			       asn1tab == tpmkey_asn1_tab_old, &privdata, &pubdata);
	if (ret < 0)
		goto out_tpmkey;

	gnutls_privkey_init(pkey);

	switch (ret) {
	case GNUTLS_PK_RSA:
#if GNUTLS_VERSION_NUMBER >= 0x030600
		gnutls_privkey_import_ext4(*pkey, certinfo, NULL, tpm2_rsa_sign_hash_fn, NULL, NULL, rsa_key_info, 0);
#else
		gnutls_privkey_import_ext(*pkey, GNUTLS_PK_RSA, certinfo, tpm2_rsa_sign_fn, NULL, 0);
#endif
		break;

	case GNUTLS_PK_ECC:
#if GNUTLS_VERSION_NUMBER >= 0x030600
		gnutls_privkey_import_ext4(*pkey, certinfo, NULL, tpm2_ec_sign_hash_fn, NULL, NULL, ec_key_info, 0);
#elif GNUTLS_VERSION_NUMBER >= 0x030400
		gnutls_privkey_import_ext3(*pkey, certinfo, tpm2_ec_sign_fn, NULL, NULL, ec_key_info, 0);
#else
		gnutls_privkey_import_ext(*pkey, GNUTLS_PK_EC, certinfo, tpm2_ec_sign_fn, NULL, 0);
#endif
		break;
	}
	ret = 0;

 out_tpmkey:
	asn1_delete_structure(&tpmkey);
	asn1_delete_structure(&tpmkey_def);
 out_asn1:
	free(asn1.data);
	return ret;
}

#if GNUTLS_VERSION_NUMBER < 0x030600
static void append_bignum(struct oc_text_buf *sig_der, const gnutls_datum_t *d)
{
	unsigned char derlen[2];
	int skip = 0;

	buf_append_bytes(sig_der, "\x02", 1); // INTEGER
	derlen[0] = d->size;
	/* If it might be interpreted as negative, prepend a zero */
	if (d->data[0] >= 0x80) {
		derlen[0]++;
		derlen[1] = 0;
		buf_append_bytes(sig_der, derlen, 2);
	} else {
		/* Skip naturally-occurring leading zeroes unless needed */
		while (skip < d->size - 1 && d->data[skip] == 0x00 &&
		       d->data[skip+1] < 0x80)
			skip++;

		buf_append_bytes(sig_der, derlen - skip, 1);
	}
	buf_append_bytes(sig_der, d->data + skip, d->size - skip);
}

int oc_gnutls_encode_rs_value(gnutls_datum_t *sig, const gnutls_datum_t *sig_r,
			      const gnutls_datum_t *sig_s)
{
	struct oc_text_buf *rs_der = NULL;
	struct oc_text_buf *sig_der = NULL;
	/*
	 * Create the DER-encoded SEQUENCE containing R and S:
	 *
	 *	Ecdsa-Sig-Value ::= SEQUENCE {
	 *	  r                   INTEGER,
	 *	  s                   INTEGER
	 *	}
	 *
	 * This is defined in RFC3279 §2.2.3 as well as SEC.1.
	 * I can't find anything which mandates DER but I've seen
	 * OpenSSL refusing to verify it with indeterminate length.
	 * So use two buffers, build the two INTEGERs first and
	 * then give a definite length.
	 */

	rs_der = buf_alloc();
	append_bignum(rs_der, sig_r);
	append_bignum(rs_der, sig_s);

	if (buf_error(rs_der))
		return buf_free(rs_der);

	sig_der = buf_alloc();
	buf_append_bytes(sig_der, "\x30", 1); // SEQUENCE
	if (rs_der->pos < 0x100) {
		unsigned char l = rs_der->pos;
		if (rs_der->pos >= 0x80)
			buf_append_bytes(sig_der, "\x81", 1);
		buf_append_bytes(sig_der, &l, 1);
	} else {
		buf_append_bytes(sig_der, "\x82", 1);
		buf_append_be16(sig_der, rs_der->pos);
	}

	buf_append_bytes(sig_der, rs_der->data, rs_der->pos);
	buf_free(rs_der);


	if (!buf_error(sig_der)) {
		sig->data = (void *)sig_der->data;
		sig->size = sig_der->pos;
		sig_der->data = NULL;
	}

	return buf_free(sig_der);
}
#endif /* GnuTLS < 3.6.0 */

/* EMSA-PKCS1-v1_5 padding in accordance with RFC3447 §9.2 */
#define PKCS1_PAD_OVERHEAD 11
static int oc_pkcs1_pad(struct openconnect_info *vpninfo,
			unsigned char *buf, int size, const gnutls_datum_t *data)
{
	if (data->size + PKCS1_PAD_OVERHEAD > size) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("TPM2 digest too large: %d > %d\n"),
			     data->size, size - PKCS1_PAD_OVERHEAD);
		return GNUTLS_E_PK_SIGN_FAILED;
	}

	buf[0] = 0;
	buf[1] = 1;
	memset(buf + 2, 0xff, size - data->size - 3);
	buf[size - data->size - 1] = 0;
	memcpy(buf + size - data->size, data->data, data->size);

	return 0;
}

#if GNUTLS_VERSION_NUMBER >= 0x030600
/* EMSA-PSS encoding in accordance with RFC3447 §9.1 */
static int oc_pss_mgf1_pad(struct openconnect_info *vpninfo, gnutls_digest_algorithm_t dig,
			   unsigned char *emBuf, int emLen, const gnutls_datum_t *mHash, int keybits)
{
	gnutls_hash_hd_t hashctx = NULL;
	int err = GNUTLS_E_PK_SIGN_FAILED;

	/* The emBits for EMSA-PSS encoding is actually one *fewer* bit than
	 * the RSA modulus. As RFC3447 §8.1.1 points out, "the octet length
	 * of EM will be one less than k if modBits - 1 is divisible by 8
	 * and equal to k otherwise". Where k is the input emLen, which we
	 * thus need to adjust before using it as emLen for the following
	 * operations. Not that it matters much since I don't think the TPM
	 * can cope with RSA keys whose modulus isn't a multiple of 8 bits
	 * anyway. */
	int msbits = (keybits - 1) & 7;
	if (!msbits) {
		*(emBuf++) = 0;
		emLen--;
	}

	/* GnuTLS gives us a predigested mHash from which we create M' and
	 * continue the process. Can we infer all the PSS parameters from
	 * the digest size, including the salt size? Or does GnuTLS need
	 * a gnutls_privkey_import_ext5() which lets us have the params too?
	 * Better still, could GnuTLS just do this all for us and we only
	 * do a raw signature — really raw, unlike GNUTLS_SIGN_RSA_RAW
	 * which AIUI is actually padded. */

	/* Actually, RFC8446 §4.2.3 mandates that the salt length MUST be
	 * equal to the length of the output of the digest algorithm. So
	 * truncating is it *wrong*.
	 *
	 *  • https://gitlab.com/gnutls/gnutls/-/issues/1258
	 *  • https://github.com/openssl/openssl/issues/16167
	 */
	int sLen = mHash->size;
	if (sLen + mHash->size > emLen - 2) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("PSS encoding failed; hash size %d too large for RSA key %d\n"),
			     mHash->size, emLen);
		return GNUTLS_E_PK_SIGN_FAILED;
	}

	/*
	 * We don't truncate salt since RFC8446 forbids it for TLSv1.3 and
	 * that's all we are using it for.
	 *
	 * if (sLen + mHash->size > emLen - 2)
	 *	sLen = emLen - 2 - mHash->size;
	 */

	char salt[SHA512_SIZE];
	if (sLen) {
		err = gnutls_rnd(GNUTLS_RND_NONCE, salt, sLen);
		if (err)
			goto out;
	}

	/* Hash M' (8 zeroes || mHash || salt) into its place in EM */
	if ((err = gnutls_hash_init(&hashctx, dig)) ||
	    (err = gnutls_hash(hashctx, "\0\0\0\0\0\0\0\0", 8)) ||
	    (err = gnutls_hash(hashctx, mHash->data, mHash->size)) ||
	    (sLen && (err = gnutls_hash(hashctx, salt, sLen))))
		goto out;

	int maskedDBLen = emLen - mHash->size - 1;
	gnutls_hash_output(hashctx, emBuf + maskedDBLen);

	emBuf[emLen - 1] = 0xbc;

	/* Although gnutls_hash_output() is supposed to reset the context,
	 * it doesn't actually seem to work at least for SHA384; the later
	 * gnutls_hash_copy() ends up wrong somehow, and gives incorrect
	 * output. Unless we completely destroy the context and make a
	 * new one. https://gitlab.com/gnutls/gnutls/-/issues/1257 */
	gnutls_hash_deinit(hashctx, NULL);
	err = gnutls_hash_init(&hashctx, dig);
	if (err) {
		hashctx = NULL;
		goto out;
	}

	/* Now the MGF1 function as defined in RFC3447 Appendix B, although
	 * it's somewhat easier to read in NIST SP 800-56B §7.2.2.2.
	 *
	 * We repeatedly hash (M' || C) where C is an incrementing 32-bit
	 * counter, so hash M' first and then use gnutls_hash_copy() each
	 * time to add C to the copy. */
	err = gnutls_hash(hashctx, emBuf + maskedDBLen, mHash->size);
	if (err)
		goto out;

	int mgflen = 0, mgf_count = 0;
	while (mgflen < maskedDBLen) {
		gnutls_hash_hd_t ctx2 = gnutls_hash_copy(hashctx);
		if (!ctx2) {
			err = GNUTLS_E_PK_SIGN_FAILED;
			goto out;
		}
		uint32_t be_count = htonl(mgf_count++);
		err = gnutls_hash(ctx2, &be_count, sizeof(be_count));
		if (err) {
			gnutls_hash_deinit(ctx2, NULL);
			goto out;
		}
		if (mgflen + mHash->size <= maskedDBLen) {
			gnutls_hash_deinit(ctx2, emBuf + mgflen);
			mgflen += mHash->size;
		} else {
			char md[SHA512_SIZE];
			gnutls_hash_deinit(ctx2, md);
			memcpy(emBuf + mgflen, md, maskedDBLen - mgflen);
			mgflen = maskedDBLen;
		}
	}

	/* Back to EMSA-PSS-ENCODE step 10. The MGF result was directly placed
	 * into emBuf, so now XOR with DB, which is (zeroes || 0x01 || salt) */
	int dst = maskedDBLen - 1;
	while (sLen--)
		emBuf[dst--] ^= salt[sLen];
	emBuf[dst] ^= 0x01;

	/* Now mask out the high bits. In the case where msbits is zero, we
	 * skipped the entire first byte so do nothing. */
	if (msbits)
		emBuf[0] &= 0xFF >> (8 - msbits);

	err = 0;
 out:
	if (hashctx)
		gnutls_hash_deinit(hashctx, NULL);

	return err;
}
#endif

int oc_pad_rsasig(struct openconnect_info *vpninfo, gnutls_sign_algorithm_t algo,
		  unsigned char *buf, int size, const gnutls_datum_t *data, int keybits)
{
	switch (algo) {
	case GNUTLS_SIGN_UNKNOWN:
	case GNUTLS_SIGN_RSA_SHA1:
	case GNUTLS_SIGN_RSA_SHA256:
	case GNUTLS_SIGN_RSA_SHA384:
	case GNUTLS_SIGN_RSA_SHA512:
		return oc_pkcs1_pad(vpninfo, buf, size, data);

#if GNUTLS_VERSION_NUMBER >= 0x030600
		/* Really PKCS#1.5 padding, yes. */
	case GNUTLS_SIGN_RSA_RAW:
		return oc_pkcs1_pad(vpninfo, buf, size, data);

	case GNUTLS_SIGN_RSA_PSS_SHA256:
	case GNUTLS_SIGN_RSA_PSS_RSAE_SHA256:
		if (data->size != SHA256_SIZE)
			return GNUTLS_E_PK_SIGN_FAILED;
		return oc_pss_mgf1_pad(vpninfo, GNUTLS_DIG_SHA256, buf, size, data, keybits);

	case GNUTLS_SIGN_RSA_PSS_SHA384:
	case GNUTLS_SIGN_RSA_PSS_RSAE_SHA384:
		if (data->size != SHA384_SIZE)
			return GNUTLS_E_PK_SIGN_FAILED;
		return oc_pss_mgf1_pad(vpninfo, GNUTLS_DIG_SHA384, buf, size, data, keybits);

	case GNUTLS_SIGN_RSA_PSS_SHA512:
	case GNUTLS_SIGN_RSA_PSS_RSAE_SHA512:
		if (data->size != SHA512_SIZE)
			return GNUTLS_E_PK_SIGN_FAILED;
		return oc_pss_mgf1_pad(vpninfo, GNUTLS_DIG_SHA512, buf, size, data, keybits);
#endif /* 3.6.0+ */
	default:
		vpn_progress(vpninfo, PRG_ERR,
			     _("TPMv2 RSA sign called for unknown algorithm %s\n"),
			     gnutls_sign_get_name(algo));
		return GNUTLS_E_PK_SIGN_FAILED;
	}
}
#endif /* HAVE_TSS2 */
