/*
 * Copyright (C) 2024 Gerardo Ravago
 *
 * Copyright (C) secunet Security Networks AG
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 */


#include "openssl_kem.h"

#include <openssl/evp.h>

#ifdef OPENSSL_IS_AWSLC
#include <openssl/experimental/kem_deterministic_api.h>

typedef struct private_key_exchange_t private_key_exchange_t;

/**
 * Private data of an key_exchange_t object.
 */
struct private_key_exchange_t {

	/**
	 * Public interface.
	 */
	key_exchange_t public;

	/**
	 * Key Exchange Method Transform ID.
	 */
	key_exchange_method_t group;

	/**
	 * OpenSSL EVP_PKEY object for a KEM Keypair. Only set on initiator.
	 */
	EVP_PKEY *pkey;

	/**
	 * Shared secret
	 */
	chunk_t shared_secret;

	/**
	 * Ciphertext. Used as the "public key" for the responder.
	 */
	chunk_t ciphertext;

	/**
	 * Deterministic Random Bit Generator (DRBG)
	 */
	drbg_t *drbg;
};

/**
 * Return the OpenSSL NID for to this instance's key_exchange_method_t.
 */
static int openssl_kem_get_nid(private_key_exchange_t *this)
{
	switch (this->group)
	{
		case ML_KEM_512:
			return NID_MLKEM512;
		case ML_KEM_768:
			return NID_MLKEM768;
		case ML_KEM_1024:
			return NID_MLKEM1024;
		default:
			return NID_undef;
	}
}

METHOD(key_exchange_t, get_method, key_exchange_method_t,
	private_key_exchange_t *this)
{
	return this->group;
}

/**
 * Call OpenSSL's KEM KeyGen method and store a reference to the key.
 */
static bool openssl_kem_generate_pkey(private_key_exchange_t *this)
{
	EVP_PKEY_CTX *ctx = NULL;
	size_t seed_length = 0;
	chunk_t seed = chunk_empty;

	ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_KEM, NULL);
	if (!ctx)
	{
		return FALSE;
	}
	if (!EVP_PKEY_CTX_kem_set_params(ctx, openssl_kem_get_nid(this)))
	{
		EVP_PKEY_CTX_free(ctx);
		return FALSE;
	}
	if (!EVP_PKEY_keygen_init(ctx))
	{
		EVP_PKEY_CTX_free(ctx);
		return FALSE;
	}
	if (this->drbg)
	{
		if (!EVP_PKEY_keygen_deterministic(ctx, NULL, NULL, &seed_length))
		{
			EVP_PKEY_CTX_free(ctx);
			return FALSE;
		}
		seed = chunk_alloc(seed_length);
		if (!this->drbg->generate(this->drbg, seed.len, seed.ptr))
		{
			EVP_PKEY_CTX_free(ctx);
			return FALSE;
		}
		if (!EVP_PKEY_keygen_deterministic(ctx, &this->pkey, seed.ptr,
										   &seed.len))
		{
			EVP_PKEY_CTX_free(ctx);
			chunk_clear(&seed);
			return FALSE;
		}
	}
	else if (!EVP_PKEY_keygen(ctx, &this->pkey))
	{
		EVP_PKEY_CTX_free(ctx);
		return FALSE;
	}
	EVP_PKEY_CTX_free(ctx);
	chunk_clear(&seed);
	return TRUE;
}

/**
 * Return the serialized form of the context's KEM public key.
 */
static bool openssl_kem_get_encoded_public_key(private_key_exchange_t *this,
											   chunk_t *out)
{
	chunk_t pkey_chunk = chunk_empty;
	size_t public_key_length = 0;

	if (!this->pkey ||
		!EVP_PKEY_get_raw_public_key(this->pkey, NULL, &public_key_length))
	{
		return FALSE;
	}
	pkey_chunk = chunk_alloc(public_key_length);
	if (!EVP_PKEY_get_raw_public_key(this->pkey, pkey_chunk.ptr,
									 &public_key_length))
	{
		chunk_free(&pkey_chunk);
		return FALSE;
	}
	*out = pkey_chunk;
	return TRUE;
}

METHOD(key_exchange_t, get_public_key, bool, private_key_exchange_t *this,
	chunk_t *value)
{
	/* responder action */
	if (this->ciphertext.ptr != NULL)
	{
		*value = chunk_clone(this->ciphertext);
		return TRUE;
	}

	/* initiator action */
	if (!this->pkey && !openssl_kem_generate_pkey(this))
	{
		return FALSE;
	}
	return openssl_kem_get_encoded_public_key(this, value);
}

METHOD(key_exchange_t, get_shared_secret, bool, private_key_exchange_t *this,
	chunk_t *secret)
{
	if (this->shared_secret.ptr != NULL)
	{
		*secret = chunk_clone(this->shared_secret);
		return TRUE;
	}
	return FALSE;
}

/**
 * Decrypt a ciphertext using the private key from the context and store a
 * reference to the resulting shared secret.
 */
static bool openssl_kem_decapsulate(private_key_exchange_t *this,
									chunk_t ciphertext)
{
	EVP_PKEY_CTX *ctx;
	size_t shared_secret_length = 0;

	ctx = EVP_PKEY_CTX_new(this->pkey, NULL);
	if (!ctx)
	{
		return FALSE;
	}
	if (!EVP_PKEY_decapsulate(ctx, NULL, &shared_secret_length, ciphertext.ptr,
							  ciphertext.len))
	{
		EVP_PKEY_CTX_free(ctx);
		return FALSE;
	}
	this->shared_secret = chunk_alloc(shared_secret_length);
	if (!EVP_PKEY_decapsulate(ctx, this->shared_secret.ptr,
							  &this->shared_secret.len, ciphertext.ptr,
							  ciphertext.len))
	{
		EVP_PKEY_CTX_free(ctx);
		chunk_clear(&this->shared_secret);
		return FALSE;
	}
	EVP_PKEY_CTX_free(ctx);
	return TRUE;
}

/**
 * Generate and store a reference to a shared secret. Use the provided public
 * key to encrypt the shared secret and store a reference to the ciphertext.
 */
static bool openssl_kem_encapsulate(private_key_exchange_t *this,
									chunk_t public_key)
{
	EVP_PKEY_CTX *ctx;
	EVP_PKEY *pkey;
	size_t shared_secret_length = 0;
	size_t ciphertext_length = 0;
	size_t seed_length = 0;
	chunk_t seed = chunk_empty;

	pkey = EVP_PKEY_kem_new_raw_public_key(openssl_kem_get_nid(this),
										   public_key.ptr, public_key.len);
	if (!pkey)
	{
		return FALSE;
	}
	ctx = EVP_PKEY_CTX_new(pkey, NULL);
	if (!ctx)
	{
		EVP_PKEY_free(pkey);
		return FALSE;
	}
	if (this->drbg)
	{
		if (!EVP_PKEY_encapsulate_deterministic(ctx, NULL, &ciphertext_length,
												NULL, &shared_secret_length,
												NULL, &seed_length))
		{
			EVP_PKEY_free(pkey);
			EVP_PKEY_CTX_free(ctx);
			return FALSE;
		}
		this->shared_secret = chunk_alloc(shared_secret_length);
		this->ciphertext = chunk_alloc(ciphertext_length);
		seed = chunk_alloc(seed_length);

		if (!this->drbg->generate(this->drbg, seed.len, seed.ptr) ||
			!EVP_PKEY_encapsulate_deterministic(ctx, this->ciphertext.ptr,
												&this->ciphertext.len,
												this->shared_secret.ptr,
												&this->shared_secret.len,
												seed.ptr, &seed.len))
		{
			EVP_PKEY_free(pkey);
			EVP_PKEY_CTX_free(ctx);
			chunk_clear(&seed);
			return FALSE;
		}
	}
	else
	{
		if (!EVP_PKEY_encapsulate(ctx, NULL, &ciphertext_length, NULL,
								  &shared_secret_length))
		{
			EVP_PKEY_free(pkey);
			EVP_PKEY_CTX_free(ctx);
			return FALSE;
		}
		this->shared_secret = chunk_alloc(shared_secret_length);
		this->ciphertext = chunk_alloc(ciphertext_length);
		if (!EVP_PKEY_encapsulate(ctx, this->ciphertext.ptr, &this->ciphertext.len,
								  this->shared_secret.ptr,
								  &this->shared_secret.len))
		{
			EVP_PKEY_free(pkey);
			EVP_PKEY_CTX_free(ctx);
			return FALSE;
		}
	}
	EVP_PKEY_free(pkey);
	EVP_PKEY_CTX_free(ctx);
	chunk_clear(&seed);
	return TRUE;
}

METHOD(key_exchange_t, set_public_key, bool, private_key_exchange_t *this,
	chunk_t value)
{
	if (this->shared_secret.ptr != NULL || this->ciphertext.ptr != NULL)
	{
		return FALSE;
	}

	/* initiator action */
	if (this->pkey)
	{
		return openssl_kem_decapsulate(this, value);
	}

	/* responder action */
	return openssl_kem_encapsulate(this, value);
}

METHOD(key_exchange_t, set_seed, bool, private_key_exchange_t *this,
	chunk_t ignore, drbg_t *seed)
{
	if (!seed)
	{
		return FALSE;
	}
	DESTROY_IF(this->drbg);
	this->drbg = seed->get_ref(seed);
	return TRUE;
}

METHOD(key_exchange_t, destroy, void, private_key_exchange_t *this)
{
	EVP_PKEY_free(this->pkey);
	chunk_clear(&this->shared_secret);
	chunk_free(&this->ciphertext);
	DESTROY_IF(this->drbg);
	free(this);
}

/*
 * Described in header.
 */
key_exchange_t *openssl_kem_create(key_exchange_method_t method)
{
	private_key_exchange_t *this;

	INIT(this,
		.public = {
			.get_shared_secret = _get_shared_secret,
			.set_public_key = _set_public_key,
			.get_public_key = _get_public_key,
			.set_seed = _set_seed,
			.get_method = _get_method,
			.destroy = _destroy,
		},
		.group = method
	);
	return &this->public;
}
#endif /* OPENSSL_IS_AWSLC */
