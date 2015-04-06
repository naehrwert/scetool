#ifndef _ECDSA_H_
#define _ECDSA_H_

int ecdsa_set_curve(u32 type);
void ecdsa_set_pub(u8 *Q);
void ecdsa_set_priv(u8 *k);
int ecdsa_verify(u8 *hash, u8 *R, u8 *S);
void ecdsa_sign(u8 *hash, u8 *R, u8 *S);
void ec_priv_to_pub(u8 *k, u8 *Q);
void elt_inv(u8 *d, u8 *a);
void get_m (u8 *r, u8 *s, u8 *e, u8 *k, u8 *m);
#endif
