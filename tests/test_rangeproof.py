import pytest

import secp256k1_zkp as secp256k1

def test_rangeproof_simple():
    '''
      Simple API checks.
    '''
    if not secp256k1.HAS_POINTS:
        pytest.skip('secp256k1_points not enabled, skipping')
        return

    pr1 = secp256k1.PrivateKey()
    pr2 = secp256k1.PrivateKey()
    pu1, pu2 = pr1.pubkey, pr2.pubkey
    p1, p2 = secp256k1.Point(pu1), secp256k1.Point(pu2)
    g1, g2 = p1.to_generator(), p2.to_generator()

    pc = secp256k1.PedersenCommitment(blinding_generator=g1, value_generator=g2)
    pc.create(3,b"\x3f"*32)

    r = secp256k1.RangeProof(pedersen_commitment=pc, additional_data = b"\x33"*32)
    with pytest.raises(AssertionError):
        # non-default blinding generator
        r._sign(exp=-1, concealed_bits=0, nonce=None) 

    pc = secp256k1.PedersenCommitment(value_generator=g2)
    pc.create(1, b"\x00"*31+b'\x01')
    r = secp256k1.RangeProof(pedersen_commitment=pc, additional_data = None)
    r._sign(exp=-1, concealed_bits=0, nonce=None) 
    assert r.verify()

