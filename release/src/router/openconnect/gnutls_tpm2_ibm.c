/*
 * OpenConnect (SSL + DTLS) VPN client
 *
 * Copyright © 2018 David Woodhouse.
 * Copyright © 2017-2018 James Bottomley
 *
 * Authors: James Bottomley <James.Bottomley@hansenpartnership.com>
 *          David Woodhouse <dwmw2@infradead.org>
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

#include <stdio.h>
#include <string.h>
#include <errno.h>

#define TSSINCLUDE(x) < HAVE_TSS2/x >
#include TSSINCLUDE(tss.h)
#include TSSINCLUDE(tssresponsecode.h)
#include TSSINCLUDE(Unmarshal_fp.h)
#include TSSINCLUDE(RSA_Decrypt_fp.h)
#include TSSINCLUDE(Sign_fp.h)

#define rc_is_key_auth_failed(rc) (((rc) & 0xff) == TPM_RC_BAD_AUTH)
#define rc_is_parent_auth_failed(rc) (((rc) & 0xff) == TPM_RC_AUTH_FAIL)

struct oc_tpm2_ctx {
	TPM2B_PUBLIC pub;
	TPM2B_PRIVATE priv;
	char *parent_pass, *key_pass;
	unsigned int need_userauth:1;
	unsigned int legacy_srk:1;
	unsigned int parent;
};

static void tpm2_error(struct openconnect_info *vpninfo, TPM_RC rc, const char *reason)
{
	const char *msg = NULL, *submsg = NULL, *num = NULL;

	TSS_ResponseCode_toString(&msg, &submsg, &num, rc);
	vpn_progress(vpninfo, PRG_ERR,
		     _("TPM2 operation %s failed (%d): %s%s%s\n"),
		     reason, rc, msg, submsg, num);
}

static TPM_RC tpm2_readpublic(struct openconnect_info *vpninfo, TSS_CONTEXT *tssContext,
			      TPM_HANDLE handle, TPMT_PUBLIC *pub)
{
	ReadPublic_In rin;
	ReadPublic_Out rout;
	TPM_RC rc;

	rin.objectHandle = handle;
	rc = TSS_Execute (tssContext,
			  (RESPONSE_PARAMETERS *)&rout,
			  (COMMAND_PARAMETERS *)&rin,
			  NULL,
			  TPM_CC_ReadPublic,
			  TPM_RH_NULL, NULL, 0);
	if (rc) {
		tpm2_error(vpninfo, rc, "TPM2_ReadPublic");
		return rc;
	}
	if (pub)
		*pub = rout.outPublic.publicArea;

	return rc;
}

static TPM_RC tpm2_get_session_handle(struct openconnect_info *vpninfo, TSS_CONTEXT *tssContext,
				      TPM_HANDLE *handle, TPM_HANDLE bind, const char *auth,
				      TPM_HANDLE salt_key)
{
	TPM_RC rc;
	StartAuthSession_In in;
	StartAuthSession_Out out;
	StartAuthSession_Extra extra;

	memset(&in, 0, sizeof(in));
	memset(&extra, 0 , sizeof(extra));
	in.bind = bind;
	extra.bindPassword = auth;
	in.sessionType = TPM_SE_HMAC;
	in.authHash = TPM_ALG_SHA256;
	in.tpmKey = TPM_RH_NULL;
	in.symmetric.algorithm = TPM_ALG_AES;
	in.symmetric.keyBits.aes = 128;
	in.symmetric.mode.aes = TPM_ALG_CFB;
	if (salt_key) {
		/* For the TSS to use a key as salt, it must have
		 * access to the public part.  It does this by keeping
		 * key files, but request the public part just to make
		 * sure*/
		tpm2_readpublic(vpninfo, tssContext, salt_key,  NULL);
		/* don't care what rout returns, the purpose of the
		 * operation was to get the public key parameters into
		 * the tss so it can construct the salt */
		in.tpmKey = salt_key;
	}
	rc = TSS_Execute(tssContext,
			 (RESPONSE_PARAMETERS *)&out,
			 (COMMAND_PARAMETERS *)&in,
			 (EXTRA_PARAMETERS *)&extra,
			 TPM_CC_StartAuthSession,
			 TPM_RH_NULL, NULL, 0);
	if (rc) {
		tpm2_error(vpninfo, rc, "TPM2_StartAuthSession");
		return rc;
	}

	*handle = out.sessionHandle;

	return TPM_RC_SUCCESS;
}

static void tpm2_flush_handle(TSS_CONTEXT *tssContext, TPM_HANDLE h)
{
	FlushContext_In in;

	if (!h)
		return;

	in.flushHandle = h;
	TSS_Execute(tssContext, NULL,
		    (COMMAND_PARAMETERS *)&in,
		    NULL,
		    TPM_CC_FlushContext,
		    TPM_RH_NULL, NULL, 0);
}


#define parent_is_generated(parent) ((parent) >> HR_SHIFT == TPM_HT_PERMANENT)
#define parent_is_persistent(parent) ((parent) >> HR_SHIFT == TPM_HT_PERSISTENT)

static TPM_RC tpm2_load_srk(struct openconnect_info *vpninfo, TSS_CONTEXT *tssContext,
			    TPM_HANDLE *h, const char *auth, TPM_HANDLE hierarchy,
			    int legacy_srk)
{
	TPM_RC rc;
	CreatePrimary_In in;
	CreatePrimary_Out out;
	TPM_HANDLE session;

	/* SPS owner */
	in.primaryHandle = hierarchy;
	if (auth) {
		in.inSensitive.sensitive.userAuth.t.size = strlen(auth);
		memcpy(in.inSensitive.sensitive.userAuth.t.buffer, auth, strlen(auth));
	} else {
		in.inSensitive.sensitive.userAuth.t.size = 0;
	}

	/* no sensitive date for storage keys */
	in.inSensitive.sensitive.data.t.size = 0;
	/* no outside info */
	in.outsideInfo.t.size = 0;
	/* no PCR state */
	in.creationPCR.count = 0;

	/* public parameters for an RSA2048 key  */
	in.inPublic.publicArea.type = TPM_ALG_ECC;
	in.inPublic.publicArea.nameAlg = TPM_ALG_SHA256;
	in.inPublic.publicArea.objectAttributes.val =
		TPMA_OBJECT_NODA |
		TPMA_OBJECT_SENSITIVEDATAORIGIN |
		TPMA_OBJECT_USERWITHAUTH |
		TPMA_OBJECT_DECRYPT |
		TPMA_OBJECT_RESTRICTED;
	if (!legacy_srk)
		in.inPublic.publicArea.objectAttributes.val |=
			TPMA_OBJECT_FIXEDPARENT | TPMA_OBJECT_FIXEDTPM;

	in.inPublic.publicArea.parameters.eccDetail.symmetric.algorithm = TPM_ALG_AES;
	in.inPublic.publicArea.parameters.eccDetail.symmetric.keyBits.aes = 128;
	in.inPublic.publicArea.parameters.eccDetail.symmetric.mode.aes = TPM_ALG_CFB;
	in.inPublic.publicArea.parameters.eccDetail.scheme.scheme = TPM_ALG_NULL;
	in.inPublic.publicArea.parameters.eccDetail.curveID = TPM_ECC_NIST_P256;
	in.inPublic.publicArea.parameters.eccDetail.kdf.scheme = TPM_ALG_NULL;

	in.inPublic.publicArea.unique.ecc.x.t.size = 0;
	in.inPublic.publicArea.unique.ecc.y.t.size = 0;
	in.inPublic.publicArea.authPolicy.t.size = 0;

	/* use a bound session here because we have no known key objects
	 * to encrypt a salt to */
	rc = tpm2_get_session_handle(vpninfo, tssContext, &session, hierarchy, auth, 0);
	if (rc)
		return rc;

	rc = TSS_Execute(tssContext,
			 (RESPONSE_PARAMETERS *)&out,
			 (COMMAND_PARAMETERS *)&in,
			 NULL,
			 TPM_CC_CreatePrimary,
			 session, auth, TPMA_SESSION_DECRYPT,
			 TPM_RH_NULL, NULL, 0);

	if (rc) {
		tpm2_error(vpninfo, rc, "TSS_CreatePrimary");
		tpm2_flush_handle(tssContext, session);
		return rc;
	}

	*h = out.objectHandle;

	return 0;
}


static TPM_HANDLE tpm2_load_key(struct openconnect_info *vpninfo, struct cert_info *certinfo, TSS_CONTEXT **tsscp)
{
	TSS_CONTEXT *tssContext;
	Load_In in;
	Load_Out out;
	TPM_HANDLE key = 0;
	TPM_RC rc;
	TPM_HANDLE session;
	char *pass = certinfo->tpm2->parent_pass;
	int need_pw = 0;

	certinfo->tpm2->parent_pass = NULL;

	rc = TSS_Create(&tssContext);
	if (rc) {
		tpm2_error(vpninfo, rc, "TSS_Create");
		return 0;
	}

	memset(&in, 0, sizeof(in));
	memset(&out, 0, sizeof(out));

	if (parent_is_persistent(certinfo->tpm2->parent)) {
		if (!pass) {
			TPMT_PUBLIC pub;
			rc = tpm2_readpublic(vpninfo, tssContext, certinfo->tpm2->parent, &pub);
			if (rc)
				goto out;

			if (!(pub.objectAttributes.val & TPMA_OBJECT_NODA))
				need_pw = 1;
		}

		in.parentHandle = certinfo->tpm2->parent;
	} else {
	reauth_srk:
		rc = tpm2_load_srk(vpninfo, tssContext, &in.parentHandle, pass, certinfo->tpm2->parent, certinfo->tpm2->legacy_srk);
		if (rc_is_key_auth_failed(rc)) {
			free_pass(&pass);
			if (!request_passphrase(vpninfo,
						certinfo_string(certinfo, "openconnect_tpm2_hierarchy",
								"openconnect_secondary_tpm2_hierarchy"),
						&pass,
						_("Enter TPM2 %s hierarchy password:"), "owner")) {
				goto reauth_srk;
			}
		}
		if (rc)
			goto out;
	}
	rc = tpm2_get_session_handle(vpninfo, tssContext, &session, 0, NULL, in.parentHandle);
	if (rc)
		goto out_flush_srk;

	memcpy(&in.inPublic, &certinfo->tpm2->pub, sizeof(in.inPublic));
	memcpy(&in.inPrivate, &certinfo->tpm2->priv, sizeof(in.inPrivate));
	if (need_pw && !pass) {
	reauth_parent:
		if (request_passphrase(vpninfo,
				       certinfo_string(certinfo, "openconnect_tpm2_parent",
						       "openconnect_secondary_tpm2_parent"),
				       &pass,
				       certinfo_string(certinfo, _("Enter TPM2 parent key password:"),
						       _("Enter secondary TPM2 parent key password:")))) {
			tpm2_flush_handle(tssContext, session);
			goto out_flush_srk;
		}
	}
	rc = TSS_Execute(tssContext,
			 (RESPONSE_PARAMETERS *)&out,
			 (COMMAND_PARAMETERS *)&in,
			 NULL,
			 TPM_CC_Load,
			 session, pass, 0,
			 TPM_RH_NULL, NULL, 0);
	if (rc_is_parent_auth_failed(rc)) {
		free_pass(&pass);
		goto reauth_parent;
	}
	if (rc) {
		tpm2_error(vpninfo, rc, "TPM2_Load");
		tpm2_flush_handle(tssContext, session);
	}
	else
		key = out.objectHandle;

 out_flush_srk:
	if (parent_is_generated(certinfo->tpm2->parent))
		tpm2_flush_handle(tssContext, in.parentHandle);
 out:
	certinfo->tpm2->parent_pass = pass;
	if (!key)
		TSS_Delete(tssContext);
	else
		*tsscp = tssContext;
	return key;
}

static void tpm2_unload_key(TSS_CONTEXT *tssContext, TPM_HANDLE key)
{
	tpm2_flush_handle(tssContext, key);

	TSS_Delete(tssContext);
}

int tpm2_rsa_sign_hash_fn(gnutls_privkey_t key, gnutls_sign_algorithm_t algo,
			  void *_certinfo, unsigned int flags,
			  const gnutls_datum_t *data, gnutls_datum_t *sig)
{
	struct cert_info *certinfo = _certinfo;
	struct openconnect_info *vpninfo = certinfo->vpninfo;
	TSS_CONTEXT *tssContext = NULL;
	RSA_Decrypt_In in;
	RSA_Decrypt_Out out;
	int ret = GNUTLS_E_PK_SIGN_FAILED;
	TPM_HANDLE authHandle;
	TPM_RC rc;
	char *pass = certinfo->tpm2->key_pass;

	certinfo->tpm2->key_pass = NULL;

	memset(&in, 0, sizeof(in));

	in.cipherText.t.size = certinfo->tpm2->pub.publicArea.unique.rsa.t.size;

	if (oc_pad_rsasig(vpninfo, algo, in.cipherText.t.buffer, in.cipherText.t.size, data,
			  certinfo->tpm2->pub.publicArea.parameters.rsaDetail.keyBits))
		return GNUTLS_E_PK_SIGN_FAILED;

	in.inScheme.scheme = TPM_ALG_NULL;
	in.keyHandle = tpm2_load_key(vpninfo, certinfo, &tssContext);
	in.label.t.size = 0;
	if (!in.keyHandle)
		return GNUTLS_E_PK_SIGN_FAILED;

	rc = tpm2_get_session_handle(vpninfo, tssContext, &authHandle, 0, NULL, 0);
	if (rc)
		goto out;

 reauth:
	rc = TSS_Execute(tssContext,
			 (RESPONSE_PARAMETERS *)&out,
			 (COMMAND_PARAMETERS *)&in,
			 NULL,
			 TPM_CC_RSA_Decrypt,
			 authHandle, pass, TPMA_SESSION_DECRYPT,
			 TPM_RH_NULL, NULL, 0);
	if (rc_is_key_auth_failed(rc)) {
		free_pass(&pass);
		if (!request_passphrase(vpninfo,
					certinfo_string(certinfo, "openconnect_tpm2_key",
							"openconnect_secondary_tpm2_key"),
					&pass,
					certinfo_string(certinfo, _("Enter TPM2 key password:"),
							_("Enter secondary TPM2 key password:"))))
			goto reauth;
	}
	if (rc) {
		tpm2_error(vpninfo, rc, "TPM2_RSA_Decrypt");
		/* failure means auth handle is not flushed */
		tpm2_flush_handle(tssContext, authHandle);
		goto out;
	}

	certinfo->tpm2->key_pass = pass;

	sig->data = malloc(out.message.t.size);
	if (!sig->data)
		goto out;

	sig->size = out.message.t.size;
	memcpy(sig->data, out.message.t.buffer, out.message.t.size);
	ret = 0;
 out:
	tpm2_unload_key(tssContext, in.keyHandle);

	return ret;
}

int tpm2_ec_sign_hash_fn(gnutls_privkey_t key, gnutls_sign_algorithm_t algo,
			 void *_certinfo, unsigned int flags,
			 const gnutls_datum_t *data, gnutls_datum_t *sig)
{
	struct cert_info *certinfo = _certinfo;
	struct openconnect_info *vpninfo = certinfo->vpninfo;
	TSS_CONTEXT *tssContext = NULL;
	Sign_In in;
	Sign_Out out;
	int ret = GNUTLS_E_PK_SIGN_FAILED;
	TPM_HANDLE authHandle;
	TPM_RC rc;
	char *pass = certinfo->tpm2->key_pass;
	gnutls_datum_t sig_r, sig_s;

	certinfo->tpm2->key_pass = NULL;

	vpn_progress(vpninfo, PRG_DEBUG,
		     _("TPM2 EC sign function called for %d bytes.\n"),
		     data->size);

	memset(&in, 0, sizeof(in));


	/* FIPS-186-4 §6.4 says "When the length of the output of the hash
	 * function is greater than the bit length of n, then the leftmost
	 * n bits of the hash function output block shall be used in any
	 * calculation using the hash function output during the generation
	 * or verification of a digital signature."
	 *
	 * So GnuTLS is expected to *truncate* a larger hash to fit the
	 * curve bit length, and then we lie to the TPM about which hash
	 * it was because the TPM only really cares about the size of the
	 * data anyway. */
	switch (data->size) {
	case SHA1_SIZE:   in.inScheme.details.ecdsa.hashAlg = TPM_ALG_SHA1;   break;
	case SHA256_SIZE: in.inScheme.details.ecdsa.hashAlg = TPM_ALG_SHA256; break;
	case SHA384_SIZE: in.inScheme.details.ecdsa.hashAlg = TPM_ALG_SHA384; break;
#ifdef TPM_ALG_SHA512
	case SHA512_SIZE: in.inScheme.details.ecdsa.hashAlg = TPM_ALG_SHA512; break;
#endif
	default:
		vpn_progress(vpninfo, PRG_ERR,
			     _("Unknown TPM2 EC digest size %d for algo 0x%x\n"),
			     data->size, algo);
		return GNUTLS_E_PK_SIGN_FAILED;
	}

	in.inScheme.scheme = TPM_ALG_ECDSA;
	in.digest.t.size = data->size;
	memcpy(in.digest.t.buffer, data->data, data->size);
	in.validation.tag = TPM_ST_HASHCHECK;
	in.validation.hierarchy = TPM_RH_NULL;
	in.validation.digest.t.size = 0;

	in.keyHandle = tpm2_load_key(vpninfo, certinfo, &tssContext);
	if (!in.keyHandle)
		return GNUTLS_E_PK_SIGN_FAILED;

	rc = tpm2_get_session_handle(vpninfo, tssContext, &authHandle, 0, NULL, 0);
	if (rc)
		goto out;

 reauth:
	rc = TSS_Execute(tssContext,
			 (RESPONSE_PARAMETERS *)&out,
			 (COMMAND_PARAMETERS *)&in,
			 NULL,
			 TPM_CC_Sign,
			 authHandle, pass, TPMA_SESSION_DECRYPT,
			 TPM_RH_NULL, NULL, 0);
	if (rc_is_key_auth_failed(rc)) {
		free_pass(&pass);
		if (!request_passphrase(vpninfo, "openconnect_tpm2_key",
					&pass, _("Enter TPM2 key password:")))
			goto reauth;
	}
	if (rc) {
		tpm2_error(vpninfo, rc, "TPM2_Sign");
		tpm2_flush_handle(tssContext, authHandle);
		goto out;
	}

	certinfo->tpm2->key_pass = pass;
	sig_r.data = out.signature.signature.ecdsa.signatureR.t.buffer;
	sig_r.size = out.signature.signature.ecdsa.signatureR.t.size;
	sig_s.data = out.signature.signature.ecdsa.signatureS.t.buffer;
	sig_s.size = out.signature.signature.ecdsa.signatureS.t.size;

	ret = gnutls_encode_rs_value(sig, &sig_r, &sig_s);
 out:
	tpm2_unload_key(tssContext, in.keyHandle);


	return ret;
}

int install_tpm2_key(struct openconnect_info *vpninfo, struct cert_info *certinfo,
		     gnutls_privkey_t *pkey, gnutls_datum_t *pkey_sig,
		     unsigned int parent, int emptyauth, int legacy,
		     gnutls_datum_t *privdata, gnutls_datum_t *pubdata)
{
	TPM_RC rc;
	BYTE *der;
	INT32 dersize;

	if (!parent_is_persistent(parent) &&
	    parent != TPM_RH_OWNER && parent != TPM_RH_NULL &&
	    parent != TPM_RH_ENDORSEMENT && parent != TPM_RH_PLATFORM) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Invalid TPM2 parent handle 0x%08x\n"), parent);
		return -EINVAL;
	}

	certinfo->tpm2 = calloc(1, sizeof(*certinfo->tpm2));
	if (!certinfo->tpm2)
		return -ENOMEM;

	certinfo->tpm2->parent = parent;
	certinfo->tpm2->need_userauth = !emptyauth;
	certinfo->tpm2->legacy_srk = legacy;

	der = privdata->data;
	dersize = privdata->size;
	rc = TPM2B_PRIVATE_Unmarshal(&certinfo->tpm2->priv, &der, &dersize);
	if (rc) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Failed to import TPM2 private key data: 0x%x\n"),
			     rc);
		goto err_out;
	}

	der = pubdata->data;
	dersize = pubdata->size;
	rc = TPM2B_PUBLIC_Unmarshal(&certinfo->tpm2->pub, &der, &dersize, FALSE);
	if (rc) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Failed to import TPM2 public key data: 0x%x\n"),
			     rc);
		goto err_out;
	}

	switch(certinfo->tpm2->pub.publicArea.type) {
	case TPM_ALG_RSA: return GNUTLS_PK_RSA;
	case TPM_ALG_ECC: return GNUTLS_PK_ECC;
	}

	vpn_progress(vpninfo, PRG_ERR,
		     _("Unsupported TPM2 key type %d\n"),
		     certinfo->tpm2->pub.publicArea.type);

 err_out:
	release_tpm2_ctx(vpninfo, certinfo);
	return -EINVAL;
}

uint16_t tpm2_key_curve(struct openconnect_info *vpninfo, struct cert_info *certinfo)
{
	return certinfo->tpm2->pub.publicArea.parameters.eccDetail.curveID;
}

int tpm2_rsa_key_bits(struct openconnect_info *vpninfo, struct cert_info *certinfo)
{
	return certinfo->tpm2->pub.publicArea.parameters.rsaDetail.keyBits;
}

void release_tpm2_ctx(struct openconnect_info *vpninfo, struct cert_info *certinfo)
{
	if (certinfo->tpm2) {
		free_pass(&certinfo->tpm2->parent_pass);
		free_pass(&certinfo->tpm2->key_pass);
		free(certinfo->tpm2);
		certinfo->tpm2 = NULL;
	}
}
