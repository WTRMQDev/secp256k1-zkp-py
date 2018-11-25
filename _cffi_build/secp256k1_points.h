typedef struct {
    unsigned char data[64];
} secp256k1_point;

/* =============Serialize/Deserialize=============  */
int secp256k1_point_parse(
    secp256k1_point* point,
    const unsigned char *input
);

int secp256k1_point_serialize(
    unsigned char *output,
    const secp256k1_point* point
);

/* =============Operations=============  */

int secp256k1_points_combine(
    secp256k1_point *out,
    const secp256k1_point * const * addends,
    size_t n
);

int secp256k1_point_mul(
    const secp256k1_context* ctx,
    secp256k1_point *point,
    const unsigned char *multiplier
);


/* =============Casts=============  */

void secp256k1_points_cast_point_to_pubkey(
    secp256k1_point* point, 
    secp256k1_pubkey* pubkey
);

void secp256k1_points_cast_pubkey_to_point(
    const secp256k1_context* ctx,
    secp256k1_pubkey* pubkey,
    secp256k1_point* point
);

void secp256k1_points_cast_point_to_generator(
    secp256k1_point* point, 
    secp256k1_generator* generator
);

void secp256k1_points_cast_generator_to_point(
    secp256k1_generator* generator,
    secp256k1_point* point
);

void secp256k1_points_cast_point_to_pedersen_commitment(
    secp256k1_point* point, 
    secp256k1_pedersen_commitment* pedersen_commitment
);

void secp256k1_points_cast_pedersen_commitment_to_point(
    secp256k1_pedersen_commitment* pedersen_commitment,
    secp256k1_point* point
);

