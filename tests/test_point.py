import pytest

import secp256k1_zkp as secp256k1

def test_point_simple():
    '''
      Simple API checks.
    '''
    if not secp256k1.HAS_POINTS:
        pytest.skip('secp256k1_points not enabled, skipping')
        return

    pr1 = secp256k1.PrivateKey()
    pr2 = secp256k1.PrivateKey()
    pu1 = pr1.pubkey
    pu2 = pr2.pubkey

    point1 = secp256k1.Point(pu1)
    point2 = secp256k1.Point(pu2)

    gen = point1.to_generator()
    pu1_sd = point1.to_pubkey()
    assert pu1.serialize()==pu1_sd.serialize()
    comm = point1.to_pedersen_commitment()

    point3 = point1 - point2
    point4 = secp256k1.Point(gen)
    point5 = secp256k1.Point(comm)

    point6 = point5*3
    point7 = point5+point5+point5
    assert point6.serialize() == point7.serialize() 

