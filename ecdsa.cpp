#include "types.h"
#include "keys.h"
#include "ecdsa.h"
#include "util.h"

int ecdsa_get_params(u32 type, u8 *p, u8 *a, u8 *b, u8 *N, u8 *Gx, u8 *Gy)
{
	curve_t *c;

	if(type & USE_VSH_CURVE)
	{
		//VSH curve.
		if((c = vsh_curve_find(type & ~USE_VSH_CURVE)) == NULL)
			return -1;
	}
	else
	{
		//Loader curve.
		if((c = curve_find(type)) == NULL)
			return -1;
	}

	_memcpy_inv(p, c->p, 20);
	_memcpy_inv(a, c->a, 20);
	_memcpy_inv(b, c->b, 20);
	_memcpy_inv(N, c->N, 21);
	_memcpy_inv(Gx, c->Gx, 20);
	_memcpy_inv(Gy, c->Gy, 20);

	return 0;
}
