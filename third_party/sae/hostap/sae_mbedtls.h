/*
 * Mbed TLS P-256/MPI adapter for Hostap's SAE crypto interface.
 */
#ifndef AX201_SAE_MBEDTLS_H
#define AX201_SAE_MBEDTLS_H

struct crypto_bignum *crypto_bignum_init(void);
struct crypto_bignum *crypto_bignum_init_set(const u8 *buf, size_t len);
struct crypto_bignum *crypto_bignum_init_uint(unsigned int value);
void crypto_bignum_deinit(struct crypto_bignum *value, int clear);
int crypto_bignum_to_bin(const struct crypto_bignum *value, u8 *buf,
			 size_t buf_len, size_t pad_len);
int crypto_bignum_rand(struct crypto_bignum *out,
		       const struct crypto_bignum *limit);
int crypto_bignum_add(const struct crypto_bignum *a,
		      const struct crypto_bignum *b,
		      struct crypto_bignum *out);
int crypto_bignum_mod(const struct crypto_bignum *a,
		      const struct crypto_bignum *modulus,
		      struct crypto_bignum *out);
int crypto_bignum_exptmod(const struct crypto_bignum *base,
			  const struct crypto_bignum *exp,
			  const struct crypto_bignum *modulus,
			  struct crypto_bignum *out);
int crypto_bignum_inverse(const struct crypto_bignum *a,
			  const struct crypto_bignum *modulus,
			  struct crypto_bignum *out);
int crypto_bignum_sub(const struct crypto_bignum *a,
		      const struct crypto_bignum *b,
		      struct crypto_bignum *out);
int crypto_bignum_div(const struct crypto_bignum *a,
		      const struct crypto_bignum *b,
		      struct crypto_bignum *out);
int crypto_bignum_addmod(const struct crypto_bignum *a,
			 const struct crypto_bignum *b,
			 const struct crypto_bignum *modulus,
			 struct crypto_bignum *out);
int crypto_bignum_mulmod(const struct crypto_bignum *a,
			 const struct crypto_bignum *b,
			 const struct crypto_bignum *modulus,
			 struct crypto_bignum *out);
int crypto_bignum_sqrmod(const struct crypto_bignum *a,
			 const struct crypto_bignum *modulus,
			 struct crypto_bignum *out);
int crypto_bignum_rshift(const struct crypto_bignum *a, int bits,
			 struct crypto_bignum *out);
int crypto_bignum_cmp(const struct crypto_bignum *a,
		      const struct crypto_bignum *b);
int crypto_bignum_is_zero(const struct crypto_bignum *value);
int crypto_bignum_is_one(const struct crypto_bignum *value);
int crypto_bignum_is_odd(const struct crypto_bignum *value);
int crypto_bignum_legendre(const struct crypto_bignum *a,
			   const struct crypto_bignum *prime);

struct crypto_ec *crypto_ec_init(int group);
void crypto_ec_deinit(struct crypto_ec *ec);
size_t crypto_ec_prime_len(struct crypto_ec *ec);
size_t crypto_ec_prime_len_bits(struct crypto_ec *ec);
size_t crypto_ec_order_len(struct crypto_ec *ec);
const struct crypto_bignum *crypto_ec_get_prime(struct crypto_ec *ec);
const struct crypto_bignum *crypto_ec_get_order(struct crypto_ec *ec);
const struct crypto_bignum *crypto_ec_get_a(struct crypto_ec *ec);
const struct crypto_bignum *crypto_ec_get_b(struct crypto_ec *ec);
struct crypto_ec_point *crypto_ec_point_init(struct crypto_ec *ec);
void crypto_ec_point_deinit(struct crypto_ec_point *point, int clear);
int crypto_ec_point_to_bin(struct crypto_ec *ec,
			   const struct crypto_ec_point *point, u8 *x, u8 *y);
struct crypto_ec_point *crypto_ec_point_from_bin(struct crypto_ec *ec,
						 const u8 *xy);
int crypto_ec_point_add(struct crypto_ec *ec,
			const struct crypto_ec_point *a,
			const struct crypto_ec_point *b,
			struct crypto_ec_point *out);
int crypto_ec_point_mul(struct crypto_ec *ec,
			const struct crypto_ec_point *point,
			const struct crypto_bignum *scalar,
			struct crypto_ec_point *out);
int crypto_ec_point_invert(struct crypto_ec *ec,
			   struct crypto_ec_point *point);
struct crypto_bignum *crypto_ec_point_compute_y_sqr(
	struct crypto_ec *ec, const struct crypto_bignum *x);
int crypto_ec_point_is_at_infinity(struct crypto_ec *ec,
				   const struct crypto_ec_point *point);
int crypto_ec_point_is_on_curve(struct crypto_ec *ec,
				const struct crypto_ec_point *point);
int crypto_ec_point_cmp(const struct crypto_ec *ec,
			const struct crypto_ec_point *a,
			const struct crypto_ec_point *b);

#endif /* AX201_SAE_MBEDTLS_H */
