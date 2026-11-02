/*
 * Mbed TLS 3.6.7 adapter for the Hostap SAE crypto interface.
 * Copyright (c) 2026 AX201 Native SAE contributors.
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "sae_port.h"
#include "sae.h"

#include <mbedtls/bignum.h>
#include <mbedtls/ecp.h>

struct crypto_bignum {
	mbedtls_mpi value;
};

struct crypto_ec {
	mbedtls_ecp_group group;
	struct crypto_bignum prime;
	struct crypto_bignum order;
	struct crypto_bignum coefficient_a;
	struct crypto_bignum coefficient_b;
};

struct crypto_ec_point {
	mbedtls_ecp_point value;
};

static int
sae_mbedtls_rng(void *context, unsigned char *output, size_t output_len)
{
	(void) context;
	return random_get_bytes(output, output_len) == 0 ? 0 : -1;
}

static struct crypto_bignum *
sae_bn_alloc(void)
{
	struct crypto_bignum *number =
		(struct crypto_bignum *) os_zalloc(sizeof(*number));
	if (number)
		mbedtls_mpi_init(&number->value);
	return number;
}

struct crypto_bignum *
crypto_bignum_init(void)
{
	return sae_bn_alloc();
}

struct crypto_bignum *
crypto_bignum_init_set(const u8 *buf, size_t len)
{
	struct crypto_bignum *number;
	if (!buf && len)
		return NULL;
	number = sae_bn_alloc();
	if (!number)
		return NULL;
	if (len && mbedtls_mpi_read_binary(&number->value, buf, len) != 0) {
		crypto_bignum_deinit(number, 1);
		return NULL;
	}
	return number;
}

struct crypto_bignum *
crypto_bignum_init_uint(unsigned int value)
{
	struct crypto_bignum *number = sae_bn_alloc();
	if (!number)
		return NULL;
	if (mbedtls_mpi_lset(&number->value, (mbedtls_mpi_sint) value) != 0) {
		crypto_bignum_deinit(number, 1);
		return NULL;
	}
	return number;
}

void
crypto_bignum_deinit(struct crypto_bignum *number, int clear)
{
	if (!number)
		return;
	(void) clear;
	mbedtls_mpi_free(&number->value);
	forced_memzero(number, sizeof(*number));
	os_free(number);
}

int
crypto_bignum_to_bin(const struct crypto_bignum *number, u8 *buf,
		     size_t buf_len, size_t pad_len)
{
	size_t value_len, output_len;
	if (!number || !buf)
		return -1;
	value_len = mbedtls_mpi_size(&number->value);
	output_len = pad_len ? pad_len : value_len;
	if (output_len > buf_len || value_len > output_len || output_len > INT_MAX)
		return -1;
	if (mbedtls_mpi_write_binary(&number->value, buf, output_len) != 0)
		return -1;
	return (int) output_len;
}

int
crypto_bignum_rand(struct crypto_bignum *out,
		   const struct crypto_bignum *limit)
{
	if (!out || !limit || mbedtls_mpi_cmp_int(&limit->value, 0) <= 0)
		return -1;
	return mbedtls_mpi_random(&out->value, 0, &limit->value,
				  sae_mbedtls_rng, NULL) == 0 ? 0 : -1;
}

int
crypto_bignum_add(const struct crypto_bignum *a,
		  const struct crypto_bignum *b,
		  struct crypto_bignum *out)
{
	if (!a || !b || !out)
		return -1;
	return mbedtls_mpi_add_mpi(&out->value, &a->value, &b->value) == 0 ?
		0 : -1;
}

int
crypto_bignum_mod(const struct crypto_bignum *a,
		  const struct crypto_bignum *modulus,
		  struct crypto_bignum *out)
{
	mbedtls_mpi result;
	int ret;
	if (!a || !modulus || !out || mbedtls_mpi_cmp_int(&modulus->value, 0) <= 0)
		return -1;
	mbedtls_mpi_init(&result);
	ret = mbedtls_mpi_mod_mpi(&result, &a->value, &modulus->value);
	if (ret == 0)
		ret = mbedtls_mpi_copy(&out->value, &result);
	mbedtls_mpi_free(&result);
	return ret == 0 ? 0 : -1;
}

int
crypto_bignum_exptmod(const struct crypto_bignum *base,
		      const struct crypto_bignum *exp,
		      const struct crypto_bignum *modulus,
		      struct crypto_bignum *out)
{
	mbedtls_mpi result;
	int ret;
	if (!base || !exp || !modulus || !out ||
	    mbedtls_mpi_cmp_int(&modulus->value, 0) <= 0 ||
	    mbedtls_mpi_cmp_int(&exp->value, 0) < 0)
		return -1;
	/* Hostap permits out to alias base, exponent, or modulus. */
	mbedtls_mpi_init(&result);
	ret = mbedtls_mpi_exp_mod(&result, &base->value, &exp->value,
				  &modulus->value, NULL);
	if (ret == 0)
		ret = mbedtls_mpi_copy(&out->value, &result);
	mbedtls_mpi_free(&result);
	return ret == 0 ? 0 : -1;
}

int
crypto_bignum_inverse(const struct crypto_bignum *a,
		      const struct crypto_bignum *modulus,
		      struct crypto_bignum *out)
{
	mbedtls_mpi result;
	int ret;
	if (!a || !modulus || !out)
		return -1;
	mbedtls_mpi_init(&result);
	ret = mbedtls_mpi_inv_mod(&result, &a->value, &modulus->value);
	if (ret == 0)
		ret = mbedtls_mpi_copy(&out->value, &result);
	mbedtls_mpi_free(&result);
	return ret == 0 ? 0 : -1;
}

int
crypto_bignum_sub(const struct crypto_bignum *a,
		  const struct crypto_bignum *b,
		  struct crypto_bignum *out)
{
	if (!a || !b || !out)
		return -1;
	return mbedtls_mpi_sub_mpi(&out->value, &a->value, &b->value) == 0 ?
		0 : -1;
}

int
crypto_bignum_div(const struct crypto_bignum *a,
		  const struct crypto_bignum *b,
		  struct crypto_bignum *out)
{
	mbedtls_mpi quotient;
	int ret;
	if (!a || !b || !out || mbedtls_mpi_cmp_int(&b->value, 0) == 0)
		return -1;
	mbedtls_mpi_init(&quotient);
	ret = mbedtls_mpi_div_mpi(&quotient, NULL, &a->value, &b->value);
	if (ret == 0)
		ret = mbedtls_mpi_copy(&out->value, &quotient);
	mbedtls_mpi_free(&quotient);
	return ret == 0 ? 0 : -1;
}

int
crypto_bignum_addmod(const struct crypto_bignum *a,
		     const struct crypto_bignum *b,
		     const struct crypto_bignum *modulus,
		     struct crypto_bignum *out)
{
	mbedtls_mpi sum;
	int ret = -1;
	if (!a || !b || !modulus || !out ||
	    mbedtls_mpi_cmp_int(&modulus->value, 0) <= 0)
		return -1;
	mbedtls_mpi_init(&sum);
	if (mbedtls_mpi_add_mpi(&sum, &a->value, &b->value) == 0 &&
	    mbedtls_mpi_mod_mpi(&out->value, &sum, &modulus->value) == 0)
		ret = 0;
	mbedtls_mpi_free(&sum);
	return ret;
}

int
crypto_bignum_mulmod(const struct crypto_bignum *a,
		     const struct crypto_bignum *b,
		     const struct crypto_bignum *modulus,
		     struct crypto_bignum *out)
{
	mbedtls_mpi product;
	int ret = -1;
	if (!a || !b || !modulus || !out ||
	    mbedtls_mpi_cmp_int(&modulus->value, 0) <= 0)
		return -1;
	mbedtls_mpi_init(&product);
	if (mbedtls_mpi_mul_mpi(&product, &a->value, &b->value) == 0 &&
	    mbedtls_mpi_mod_mpi(&out->value, &product, &modulus->value) == 0)
		ret = 0;
	mbedtls_mpi_free(&product);
	return ret;
}

int
crypto_bignum_sqrmod(const struct crypto_bignum *a,
		     const struct crypto_bignum *modulus,
		     struct crypto_bignum *out)
{
	return crypto_bignum_mulmod(a, a, modulus, out);
}

int
crypto_bignum_rshift(const struct crypto_bignum *a, int bits,
		     struct crypto_bignum *out)
{
	if (!a || !out || bits < 0)
		return -1;
	if (mbedtls_mpi_copy(&out->value, &a->value) != 0 ||
	    mbedtls_mpi_shift_r(&out->value, (size_t) bits) != 0)
		return -1;
	return 0;
}

int
crypto_bignum_cmp(const struct crypto_bignum *a,
		  const struct crypto_bignum *b)
{
	if (!a || !b)
		return 0;
	return mbedtls_mpi_cmp_mpi(&a->value, &b->value);
}

int
crypto_bignum_is_zero(const struct crypto_bignum *number)
{
	return number && mbedtls_mpi_cmp_int(&number->value, 0) == 0;
}

int
crypto_bignum_is_one(const struct crypto_bignum *number)
{
	return number && mbedtls_mpi_cmp_int(&number->value, 1) == 0;
}

int
crypto_bignum_is_odd(const struct crypto_bignum *number)
{
	return number && mbedtls_mpi_get_bit(&number->value, 0) != 0;
}

int
crypto_bignum_legendre(const struct crypto_bignum *a,
		       const struct crypto_bignum *prime)
{
	mbedtls_mpi exponent, result, one, pm1;
	int symbol = -2;

	if (!a || !prime || mbedtls_mpi_cmp_int(&prime->value, 2) <= 0)
		return -2;
	if (crypto_bignum_is_zero(a))
		return 0;
	mbedtls_mpi_init(&exponent);
	mbedtls_mpi_init(&result);
	mbedtls_mpi_init(&one);
	mbedtls_mpi_init(&pm1);
	if (mbedtls_mpi_lset(&one, 1) != 0 ||
	    mbedtls_mpi_sub_mpi(&exponent, &prime->value, &one) != 0 ||
	    mbedtls_mpi_shift_r(&exponent, 1) != 0 ||
	    mbedtls_mpi_exp_mod(&result, &a->value, &exponent,
			 &prime->value, NULL) != 0 ||
	    mbedtls_mpi_sub_mpi(&pm1, &prime->value, &one) != 0)
		goto done;
	if (mbedtls_mpi_cmp_int(&result, 1) == 0)
		symbol = 1;
	else if (mbedtls_mpi_cmp_mpi(&result, &pm1) == 0)
		symbol = -1;
	else if (mbedtls_mpi_cmp_int(&result, 0) == 0)
		symbol = 0;
done:
	mbedtls_mpi_free(&exponent);
	mbedtls_mpi_free(&result);
	mbedtls_mpi_free(&one);
	mbedtls_mpi_free(&pm1);
	return symbol;
}

struct crypto_ec *
crypto_ec_init(int group)
{
	struct crypto_ec *ec;
	int ret;

	if (group != 19)
		return NULL;
	ec = (struct crypto_ec *) os_zalloc(sizeof(*ec));
	if (!ec)
		return NULL;
	mbedtls_ecp_group_init(&ec->group);
	mbedtls_mpi_init(&ec->prime.value);
	mbedtls_mpi_init(&ec->order.value);
	mbedtls_mpi_init(&ec->coefficient_a.value);
	mbedtls_mpi_init(&ec->coefficient_b.value);
	ret = mbedtls_ecp_group_load(&ec->group, MBEDTLS_ECP_DP_SECP256R1);
	if (ret == 0)
		ret = mbedtls_mpi_copy(&ec->prime.value, &ec->group.P);
	if (ret == 0)
		ret = mbedtls_mpi_copy(&ec->order.value, &ec->group.N);
	if (ret == 0)
		ret = mbedtls_mpi_lset(&ec->coefficient_a.value, 3);
	if (ret == 0)
		ret = mbedtls_mpi_sub_mpi(&ec->coefficient_a.value,
					  &ec->group.P,
					  &ec->coefficient_a.value);
	if (ret == 0)
		ret = mbedtls_mpi_copy(&ec->coefficient_b.value, &ec->group.B);
	if (ret != 0) {
		crypto_ec_deinit(ec);
		return NULL;
	}
	return ec;
}

void
crypto_ec_deinit(struct crypto_ec *ec)
{
	if (!ec)
		return;
	mbedtls_ecp_group_free(&ec->group);
	mbedtls_mpi_free(&ec->prime.value);
	mbedtls_mpi_free(&ec->order.value);
	mbedtls_mpi_free(&ec->coefficient_a.value);
	mbedtls_mpi_free(&ec->coefficient_b.value);
	forced_memzero(ec, sizeof(*ec));
	os_free(ec);
}

size_t
crypto_ec_prime_len(struct crypto_ec *ec)
{
	return ec ? (ec->group.pbits + 7) / 8 : 0;
}

size_t
crypto_ec_prime_len_bits(struct crypto_ec *ec)
{
	return ec ? ec->group.pbits : 0;
}

size_t
crypto_ec_order_len(struct crypto_ec *ec)
{
	return ec ? (ec->group.nbits + 7) / 8 : 0;
}

const struct crypto_bignum *
crypto_ec_get_prime(struct crypto_ec *ec)
{
	return ec ? &ec->prime : NULL;
}

const struct crypto_bignum *
crypto_ec_get_order(struct crypto_ec *ec)
{
	return ec ? &ec->order : NULL;
}

const struct crypto_bignum *
crypto_ec_get_a(struct crypto_ec *ec)
{
	return ec ? &ec->coefficient_a : NULL;
}

const struct crypto_bignum *
crypto_ec_get_b(struct crypto_ec *ec)
{
	return ec ? &ec->coefficient_b : NULL;
}

struct crypto_ec_point *
crypto_ec_point_init(struct crypto_ec *ec)
{
	struct crypto_ec_point *point;
	if (!ec)
		return NULL;
	point = (struct crypto_ec_point *) os_zalloc(sizeof(*point));
	if (point)
		mbedtls_ecp_point_init(&point->value);
	return point;
}

void
crypto_ec_point_deinit(struct crypto_ec_point *point, int clear)
{
	if (!point)
		return;
	(void) clear;
	mbedtls_ecp_point_free(&point->value);
	forced_memzero(point, sizeof(*point));
	os_free(point);
}

static int
sae_point_write(const struct crypto_ec *ec,
		const struct crypto_ec_point *point, u8 *out)
{
	size_t written = 0;
	if (!ec || !point || !out)
		return -1;
	if (mbedtls_ecp_point_write_binary(&ec->group, &point->value,
					   MBEDTLS_ECP_PF_UNCOMPRESSED,
					   &written, out,
					   1 + 2 * crypto_ec_prime_len((struct crypto_ec *) ec)) != 0 ||
	    written != 1 + 2 * crypto_ec_prime_len((struct crypto_ec *) ec))
		return -1;
	return 0;
}

int
crypto_ec_point_to_bin(struct crypto_ec *ec,
		       const struct crypto_ec_point *point, u8 *x, u8 *y)
{
	u8 encoded[1 + 2 * SAE_MAX_ECC_PRIME_LEN];
	size_t prime_len;
	int ret = -1;

	if (!ec || !point || (!x && !y))
		return -1;
	prime_len = crypto_ec_prime_len(ec);
	if (prime_len == 0 || prime_len > SAE_MAX_ECC_PRIME_LEN ||
	    sae_point_write(ec, point, encoded) != 0)
		goto done;
	if (x)
		os_memcpy(x, encoded + 1, prime_len);
	if (y)
		os_memcpy(y, encoded + 1 + prime_len, prime_len);
	ret = 0;
done:
	forced_memzero(encoded, sizeof(encoded));
	return ret;
}

struct crypto_ec_point *
crypto_ec_point_from_bin(struct crypto_ec *ec, const u8 *xy)
{
	u8 encoded[1 + 2 * SAE_MAX_ECC_PRIME_LEN];
	struct crypto_ec_point *point;
	size_t prime_len;
	int read_ret, check_ret = -1;

	if (!ec || !xy)
		return NULL;
	prime_len = crypto_ec_prime_len(ec);
	if (prime_len == 0 || prime_len > SAE_MAX_ECC_PRIME_LEN)
		return NULL;
	encoded[0] = 0x04;
	os_memcpy(encoded + 1, xy, 2 * prime_len);
	point = crypto_ec_point_init(ec);
	read_ret = point ? mbedtls_ecp_point_read_binary(&ec->group,
		&point->value, encoded, 1 + 2 * prime_len) : -1;
	if (point && read_ret == 0)
		check_ret = mbedtls_ecp_check_pubkey(&ec->group, &point->value);
	if (!point || read_ret != 0 || check_ret != 0) {
		wpa_printf(MSG_DEBUG, "SAE point import failed read=%d check=%d",
			   read_ret, check_ret);
		crypto_ec_point_deinit(point, 1);
		point = NULL;
	}
	forced_memzero(encoded, sizeof(encoded));
	return point;
}

int
crypto_ec_point_add(struct crypto_ec *ec,
		    const struct crypto_ec_point *a,
		    const struct crypto_ec_point *b,
		    struct crypto_ec_point *out)
{
	mbedtls_mpi one;
	mbedtls_ecp_point result;
	int ret;
	if (!ec || !a || !b || !out)
		return -1;
	mbedtls_mpi_init(&one);
	mbedtls_ecp_point_init(&result);
	ret = mbedtls_mpi_lset(&one, 1);
	if (ret == 0)
		ret = mbedtls_ecp_muladd(&ec->group, &result, &one,
					 &a->value, &one, &b->value);
	if (ret == 0)
		ret = mbedtls_ecp_copy(&out->value, &result);
	mbedtls_mpi_free(&one);
	mbedtls_ecp_point_free(&result);
	return ret == 0 ? 0 : -1;
}

int
crypto_ec_point_mul(struct crypto_ec *ec,
		    const struct crypto_ec_point *point,
		    const struct crypto_bignum *scalar,
		    struct crypto_ec_point *out)
{
	mbedtls_ecp_point result;
	int ret;
	if (!ec || !point || !scalar || !out)
		return -1;
	mbedtls_ecp_point_init(&result);
	ret = mbedtls_ecp_mul(&ec->group, &result, &scalar->value,
			      &point->value, sae_mbedtls_rng, NULL);
	if (ret == 0)
		ret = mbedtls_ecp_copy(&out->value, &result);
	mbedtls_ecp_point_free(&result);
	return ret == 0 ? 0 : -1;
}

int
crypto_ec_point_invert(struct crypto_ec *ec, struct crypto_ec_point *point)
{
	u8 encoded[1 + 2 * SAE_MAX_ECC_PRIME_LEN];
	size_t prime_len;
	mbedtls_mpi y;
	mbedtls_ecp_point negated;
	int ret = -1;

	if (!ec || !point)
		return -1;
	if (mbedtls_ecp_is_zero(&point->value))
		return 0;
	prime_len = crypto_ec_prime_len(ec);
	if (!prime_len || prime_len > SAE_MAX_ECC_PRIME_LEN ||
	    sae_point_write(ec, point, encoded) != 0)
		goto done;
	mbedtls_mpi_init(&y);
	mbedtls_ecp_point_init(&negated);
	if (mbedtls_mpi_read_binary(&y, encoded + 1 + prime_len, prime_len) == 0 &&
	    mbedtls_mpi_sub_mpi(&y, &ec->group.P, &y) == 0 &&
	    mbedtls_mpi_mod_mpi(&y, &y, &ec->group.P) == 0 &&
	    mbedtls_mpi_write_binary(&y, encoded + 1 + prime_len, prime_len) == 0 &&
	    mbedtls_ecp_point_read_binary(&ec->group, &negated, encoded,
					  1 + 2 * prime_len) == 0 &&
	    mbedtls_ecp_check_pubkey(&ec->group, &negated) == 0 &&
	    mbedtls_ecp_copy(&point->value, &negated) == 0)
		ret = 0;
	mbedtls_mpi_free(&y);
	mbedtls_ecp_point_free(&negated);
done:
	forced_memzero(encoded, sizeof(encoded));
	return ret;
}

struct crypto_bignum *
crypto_ec_point_compute_y_sqr(struct crypto_ec *ec,
			      const struct crypto_bignum *x)
{
	struct crypto_bignum *result;
	mbedtls_mpi x2, x3, ax;
	int ok = 0;

	if (!ec || !x)
		return NULL;
	result = crypto_bignum_init();
	if (!result)
		return NULL;
	mbedtls_mpi_init(&x2);
	mbedtls_mpi_init(&x3);
	mbedtls_mpi_init(&ax);
	if (mbedtls_mpi_mul_mpi(&x2, &x->value, &x->value) == 0 &&
	    mbedtls_mpi_mod_mpi(&x2, &x2, &ec->group.P) == 0 &&
	    mbedtls_mpi_mul_mpi(&x3, &x2, &x->value) == 0 &&
	    mbedtls_mpi_mod_mpi(&x3, &x3, &ec->group.P) == 0 &&
	    mbedtls_mpi_mul_mpi(&ax, &ec->coefficient_a.value,
			&x->value) == 0 &&
	    mbedtls_mpi_mod_mpi(&ax, &ax, &ec->group.P) == 0 &&
	    mbedtls_mpi_add_mpi(&result->value, &x3, &ax) == 0 &&
	    mbedtls_mpi_add_mpi(&result->value, &result->value,
				 &ec->group.B) == 0 &&
	    mbedtls_mpi_mod_mpi(&result->value, &result->value,
				&ec->group.P) == 0)
		ok = 1;
	mbedtls_mpi_free(&x2);
	mbedtls_mpi_free(&x3);
	mbedtls_mpi_free(&ax);
	if (!ok) {
		crypto_bignum_deinit(result, 1);
		return NULL;
	}
	return result;
}

int
crypto_ec_point_is_at_infinity(struct crypto_ec *ec,
			       const struct crypto_ec_point *point)
{
	(void) ec;
	return point && mbedtls_ecp_is_zero((mbedtls_ecp_point *) &point->value);
}

int
crypto_ec_point_is_on_curve(struct crypto_ec *ec,
			    const struct crypto_ec_point *point)
{
	return ec && point && !mbedtls_ecp_is_zero(
		(mbedtls_ecp_point *) &point->value) &&
		mbedtls_ecp_check_pubkey(&ec->group, &point->value) == 0;
}

int
crypto_ec_point_cmp(const struct crypto_ec *ec,
		    const struct crypto_ec_point *a,
		    const struct crypto_ec_point *b)
{
	u8 a_bin[1 + 2 * SAE_MAX_ECC_PRIME_LEN];
	u8 b_bin[1 + 2 * SAE_MAX_ECC_PRIME_LEN];
	int a_zero, b_zero, ret = 1;

	if (!ec || !a || !b)
		return 1;
	a_zero = mbedtls_ecp_is_zero((mbedtls_ecp_point *) &a->value);
	b_zero = mbedtls_ecp_is_zero((mbedtls_ecp_point *) &b->value);
	if (a_zero || b_zero)
		return a_zero == b_zero ? 0 : 1;
	if (sae_point_write(ec, a, a_bin) == 0 &&
	    sae_point_write(ec, b, b_bin) == 0)
		ret = const_time_memcmp(a_bin, b_bin,
			1 + 2 * crypto_ec_prime_len((struct crypto_ec *) ec)) == 0 ?
			0 : 1;
	forced_memzero(a_bin, sizeof(a_bin));
	forced_memzero(b_bin, sizeof(b_bin));
	return ret;
}
