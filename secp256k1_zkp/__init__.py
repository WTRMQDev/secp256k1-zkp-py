import os
import hashlib
import binascii

from ._libsecp256k1 import ffi, lib


EC_COMPRESSED = lib.SECP256K1_EC_COMPRESSED
EC_UNCOMPRESSED = lib.SECP256K1_EC_UNCOMPRESSED

FLAG_SIGN = lib.SECP256K1_CONTEXT_SIGN
FLAG_VERIFY = lib.SECP256K1_CONTEXT_VERIFY
ALL_FLAGS = FLAG_SIGN | FLAG_VERIFY
NO_FLAGS = lib.SECP256K1_CONTEXT_NONE

HAS_RECOVERABLE = hasattr(lib, 'secp256k1_ecdsa_sign_recoverable')
HAS_SCHNORR = hasattr(lib, 'secp256k1_schnorr_sign')
HAS_ECDH = hasattr(lib, 'secp256k1_ecdh')
HAS_POINTS = hasattr(lib, 'secp256k1_points_cast_pubkey_to_point')
HAS_RANGEPROOFS = hasattr(lib, 'secp256k1_rangeproof_sign')
HAS_BULLETROOFS = hasattr(lib, 'secp256k1_bulletproof_generators_create')


class Base(object):

    def __init__(self, ctx, flags):
        self._destroy = None
        if ctx is None:
            assert flags in (NO_FLAGS, FLAG_SIGN, FLAG_VERIFY, ALL_FLAGS)
            ctx = lib.secp256k1_context_create(flags)
            self._destroy = lib.secp256k1_context_destroy

        self.flags = flags
        self.ctx = ctx

    def __del__(self):
        if not hasattr(self, '_destroy'):
            return

        if self._destroy and self.ctx:
            self._destroy(self.ctx)
            self.ctx = None


class ECDSA:  # Use as a mixin; instance.ctx is assumed to exist.

    def ecdsa_serialize(self, raw_sig):
        len_sig = 74
        output = ffi.new('unsigned char[%d]' % len_sig)
        outputlen = ffi.new('size_t *', len_sig)

        res = lib.secp256k1_ecdsa_signature_serialize_der(
            self.ctx, output, outputlen, raw_sig)
        assert res == 1

        return bytes(ffi.buffer(output, outputlen[0]))

    def ecdsa_deserialize(self, ser_sig):
        raw_sig = ffi.new('secp256k1_ecdsa_signature *')
        res = lib.secp256k1_ecdsa_signature_parse_der(
            self.ctx, raw_sig, ser_sig, len(ser_sig))
        assert res == 1

        return raw_sig

    def ecdsa_serialize_compact(self, raw_sig):
        len_sig = 64
        output = ffi.new('unsigned char[%d]' % len_sig)

        res = lib.secp256k1_ecdsa_signature_serialize_compact(
            self.ctx, output, raw_sig)
        assert res == 1

        return bytes(ffi.buffer(output, len_sig))

    def ecdsa_deserialize_compact(self, ser_sig):
        if len(ser_sig) != 64:
            raise Exception("invalid signature length")

        raw_sig = ffi.new('secp256k1_ecdsa_signature *')
        res = lib.secp256k1_ecdsa_signature_parse_compact(
            self.ctx, raw_sig, ser_sig)
        assert res == 1

        return raw_sig

    def ecdsa_signature_normalize(self, raw_sig, check_only=False):
        """
        Check and optionally convert a signature to a normalized lower-S form.
        If check_only is True then the normalized signature is not returned.

        This function always return a tuple containing a boolean (True if
        not previously normalized or False if signature was already
        normalized), and the normalized signature. When check_only is True,
        the normalized signature returned is always None.
        """
        if check_only:
            sigout = ffi.NULL
        else:
            sigout = ffi.new('secp256k1_ecdsa_signature *')

        result = lib.secp256k1_ecdsa_signature_normalize(
            self.ctx, sigout, raw_sig)

        return (bool(result), sigout if sigout != ffi.NULL else None)

    def ecdsa_recover(self, msg, recover_sig, raw=False, digest=hashlib.sha256):
        if not HAS_RECOVERABLE:
            raise Exception("secp256k1_recovery not enabled")
        if self.flags & ALL_FLAGS != ALL_FLAGS:
            raise Exception("instance not configured for ecdsa recover")

        msg32 = _hash32(msg, raw, digest)
        pubkey = ffi.new('secp256k1_pubkey *')

        recovered = lib.secp256k1_ecdsa_recover(
            self.ctx, pubkey, recover_sig, msg32)
        if recovered:
            return pubkey
        raise Exception('failed to recover ECDSA public key')

    def ecdsa_recoverable_serialize(self, recover_sig):
        if not HAS_RECOVERABLE:
            raise Exception("secp256k1_recovery not enabled")

        outputlen = 64
        output = ffi.new('unsigned char[%d]' % outputlen)
        recid = ffi.new('int *')

        lib.secp256k1_ecdsa_recoverable_signature_serialize_compact(
            self.ctx, output, recid, recover_sig)

        return bytes(ffi.buffer(output, outputlen)), recid[0]

    def ecdsa_recoverable_serialize_raw(self, recover_sig):
        sig, _id = self.ecdsa_recoverable_serialize(recover_sig)
        return _int_to_bytes(_id,1,'big')+sig

    def ecdsa_recoverable_deserialize(self, ser_sig, rec_id):
        if not HAS_RECOVERABLE:
            raise Exception("secp256k1_recovery not enabled")
        if rec_id < 0 or rec_id > 3:
            raise Exception("invalid rec_id")
        if len(ser_sig) != 64:
            raise Exception("invalid signature length")

        recover_sig = ffi.new('secp256k1_ecdsa_recoverable_signature *')

        parsed = lib.secp256k1_ecdsa_recoverable_signature_parse_compact(
            self.ctx, recover_sig, ser_sig, rec_id)
        if parsed:
            return recover_sig
        else:
            raise Exception('failed to parse ECDSA compact sig')

    def ecdsa_recoverable_deserialize_raw(self, recover_sig):
        return self.ecdsa_recoverable_deserialize(recover_sig[1:], _bytes_to_int(recover_sig[0:1]))

    def ecdsa_recoverable_convert(self, recover_sig):
        if not HAS_RECOVERABLE:
            raise Exception("secp256k1_recovery not enabled")

        normal_sig = ffi.new('secp256k1_ecdsa_signature *')

        lib.secp256k1_ecdsa_recoverable_signature_convert(
            self.ctx, normal_sig, recover_sig)

        return normal_sig


def drop_serialized(f):
  def g(self, *args, **kwargs):
    self.serialized = None
    return f(self, *args, **kwargs)
  return g

class PublicKey(Base, ECDSA):
    @drop_serialized
    def __init__(self, pubkey=None, raw=False, flags=FLAG_VERIFY, ctx=None):
        Base.__init__(self, ctx, flags)
        if pubkey is not None:
            if raw:
                if not isinstance(pubkey, bytes):
                    raise TypeError('raw pubkey must be bytes')
                self.public_key = self.deserialize(pubkey)
            else:
                if not isinstance(pubkey, ffi.CData):
                    raise TypeError('pubkey must be an internal object')
                assert ffi.typeof(pubkey) is ffi.typeof('secp256k1_pubkey *')
                self.public_key = pubkey
        else:
            self.public_key = None

    def serialize(self, compressed=True):
        if self.serialized and compressed:
          return self.serialized

        assert self.public_key, "No public key defined"

        len_compressed = 33 if compressed else 65
        res_compressed = ffi.new('char [%d]' % len_compressed)
        outlen = ffi.new('size_t *', len_compressed)
        compflag = EC_COMPRESSED if compressed else EC_UNCOMPRESSED

        serialized = lib.secp256k1_ec_pubkey_serialize(
            self.ctx, res_compressed, outlen, self.public_key, compflag)
        assert serialized == 1
        if compressed:
          self.serialized = bytes(ffi.buffer(res_compressed, len_compressed))
        return bytes(ffi.buffer(res_compressed, len_compressed))

    def deserialize(self, pubkey_ser):
        if len(pubkey_ser) not in (33, 65):
            raise Exception("unknown public key size (expected 33 or 65)")

        pubkey = ffi.new('secp256k1_pubkey *')

        res = lib.secp256k1_ec_pubkey_parse(
            self.ctx, pubkey, pubkey_ser, len(pubkey_ser))
        if not res:
            raise Exception("invalid public key")

        self.serialized = pubkey_ser
        self.public_key = pubkey
        return pubkey

    @drop_serialized
    def combine(self, pubkeys):
        """Add a number of public keys together."""
        assert len(pubkeys) > 0

        outpub = ffi.new('secp256k1_pubkey *')
        for item in pubkeys:
            assert ffi.typeof(item) is ffi.typeof('secp256k1_pubkey *')

        res = lib.secp256k1_ec_pubkey_combine(
            self.ctx, outpub, pubkeys, len(pubkeys))
        if not res:
            raise Exception('failed to combine public keys')

        self.public_key = outpub
        return outpub

    @drop_serialized
    def tweak_add(self, scalar):
        """
        Tweak the current public key by adding a 32 byte scalar times
        the generator to it and return a new PublicKey instance.
        """
        return _tweak_public(self, lib.secp256k1_ec_pubkey_tweak_add, scalar)

    @drop_serialized
    def tweak_mul(self, scalar):
        """
        Tweak the current public key by multiplying it by a 32 byte scalar
        and return a new PublicKey instance.
        """
        return _tweak_public(self, lib.secp256k1_ec_pubkey_tweak_mul, scalar)

    def ecdsa_verify(self, msg, raw_sig, raw=False, digest=hashlib.sha256):
        assert self.public_key, "No public key defined"
        if self.flags & FLAG_VERIFY != FLAG_VERIFY:
            raise Exception("instance not configured for sig verification")

        msg32 = _hash32(msg, raw, digest)

        verified = lib.secp256k1_ecdsa_verify(
            self.ctx, raw_sig, msg32, self.public_key)

        return bool(verified)

    def ecdh(self, scalar):
        assert self.public_key, "No public key defined"
        if not HAS_ECDH:
            raise Exception("secp256k1_ecdh not enabled")
        if not isinstance(scalar, bytes) or len(scalar) != 32:
            raise TypeError('scalar must be composed of 32 bytes')

        result = ffi.new('char [32]')

        res = lib.secp256k1_ecdh(self.ctx, result, self.public_key, scalar)
        if not res:
            raise Exception('invalid scalar ({})'.format(res))

        return bytes(ffi.buffer(result, 32))

    def __add__(self, pubkey2):
        if isinstance(pubkey2, PublicKey):
            new_pub= PublicKey(ctx=self.ctx)
            new_pub.combine([self.public_key, pubkey2.public_key])
            return new_pub
        else:
            raise TypeError("Cant add pubkey and %s"%pubkey2.__class__)

    def __neg__(self):
        serialized=self.serialize()
        first_byte, remainder = serialized[:1], serialized[1:]
        first_byte = {b'\x03':b'\x02', b'\x02':b'\x03'}[first_byte]
        return PublicKey(first_byte+ remainder, raw=True)

    def __sub__(self, pubkey2):
        if isinstance(pubkey2, PublicKey):
            return self + (-pubkey2)
        else:
            raise TypeError("Cant add pubkey and %s"%pubkey2.__class__)

    def to_pedersen_commitment(self, flags=ALL_FLAGS, ctx=None, blinding_generator=None):
        """Generate pedersen commitment r*G+0*H from r*G"""
        assert self.public_key
       
        point = ffi.new('secp256k1_point *')
        commitment = ffi.new('secp256k1_pedersen_commitment *')

        lib.secp256k1_points_cast_pubkey_to_point(
            self.ctx, self.public_key, point)
        lib.secp256k1_points_cast_point_to_pedersen_commitment(point, commitment)

        return PedersenCommitment(commitment, raw=False, flags=flags, ctx=ctx, blinding_generator=blinding_generator)


def _int_to_bytes(n, length, endianess='big'):
    try:
        return n.to_bytes(length, endianess)
    except:
        h = '%x' % n
        s = ('0'*(len(h) % 2) + h).zfill(length*2).decode('hex')
        return s if endianess == 'big' else s[::-1]

def _bytes_to_int(bt, endianess='big'):
    try:
        return int.from_bytes(bt, endianess)
    except:
        bt = bt if endianess == 'big' else bt[::-1]
        bt = bytearray(bt)
        n=0
        for m in bt:
          n *= 256
          n+=int(m)
        return n
            


class PrivateKey(Base, ECDSA):

    def __init__(self, privkey=None, raw=True, flags=ALL_FLAGS, ctx=None):
        assert flags in (ALL_FLAGS, FLAG_SIGN)

        Base.__init__(self, ctx, flags)
        self.pubkey = None
        self.private_key = None
        if privkey is None:
            self.set_raw_privkey(_gen_private_key())
        else:
            if raw:
                if not isinstance(privkey, bytes) or len(privkey) != 32:
                    raise TypeError('privkey must be composed of 32 bytes')
                self.set_raw_privkey(privkey)
            else:
                self.deserialize(privkey)

    def _update_public_key(self):
        public_key = self._gen_public_key(self.private_key)
        self.pubkey = PublicKey(
            public_key, raw=False, ctx=self.ctx, flags=self.flags)

    def set_raw_privkey(self, privkey):
        if not lib.secp256k1_ec_seckey_verify(self.ctx, privkey):
            raise Exception("invalid private key")
        self.private_key = privkey
        self._update_public_key()

    def serialize(self):
        hexkey = binascii.hexlify(self.private_key)
        return hexkey.decode('utf8')

    def deserialize(self, privkey_ser):
        if len(privkey_ser) != 64:
            raise Exception("invalid private key")
        rawkey = binascii.unhexlify(privkey_ser)

        self.set_raw_privkey(rawkey)
        return self.private_key

    def _gen_public_key(self, privkey):
        pubkey_ptr = ffi.new('secp256k1_pubkey *')

        created = lib.secp256k1_ec_pubkey_create(self.ctx, pubkey_ptr, privkey)
        assert created == 1

        return pubkey_ptr

    def tweak_add(self, scalar):
        """
        Tweak the current private key by adding a 32 byte scalar
        to it and return a new raw private key composed of 32 bytes.
        """
        return _tweak_private(self, lib.secp256k1_ec_privkey_tweak_add, scalar)

    def tweak_mul(self, scalar):
        """
        Tweak the current private key by multiplying it by a 32 byte scalar
        and return a new raw private key composed of 32 bytes.
        """
        return _tweak_private(self, lib.secp256k1_ec_privkey_tweak_mul, scalar)

    def ecdsa_sign(self, msg, raw=False, digest=hashlib.sha256, custom_nonce=None):
        msg32 = _hash32(msg, raw, digest)
        raw_sig = ffi.new('secp256k1_ecdsa_signature *')
        nonce_fn = ffi.NULL
        nonce_data = ffi.NULL
        if custom_nonce:
            nonce_fn, nonce_data = custom_nonce
        signed = lib.secp256k1_ecdsa_sign(
            self.ctx, raw_sig, msg32, self.private_key, nonce_fn, nonce_data)
        assert signed == 1

        return raw_sig

    def ecdsa_sign_recoverable(self, msg, raw=False, digest=hashlib.sha256):
        if not HAS_RECOVERABLE:
            raise Exception("secp256k1_recovery not enabled")

        msg32 = _hash32(msg, raw, digest)
        raw_sig = ffi.new('secp256k1_ecdsa_recoverable_signature *')

        signed = lib.secp256k1_ecdsa_sign_recoverable(
            self.ctx, raw_sig, msg32, self.private_key, ffi.NULL, ffi.NULL)
        assert signed == 1

        return raw_sig

    def __add__(self, privkey2):
      if not isinstance(privkey2, PrivateKey):
        raise TypeError("Cant summarize privkey and %s"%privkey2.__class__)
      return PrivateKey(self.tweak_add(privkey2.private_key), raw = True )

    def __mul__(self, privkey2):
      if isinstance(privkey2, PrivateKey):
        return PrivateKey(self.tweak_mul(privkey2.private_key), raw = True )
      else:
        return PrivateKey(self.tweak_mul(_int_to_bytes(privkey2, 32)), raw = True  )

    def __neg__(self):
      order = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141 #order of secp256k1 group
      neg_num=_int_to_bytes(order-_bytes_to_int(self.private_key, 'big'), 32, 'big')
      return PrivateKey(neg_num, raw=True)

    def __sub__(self, privkey2):
      return self + (-privkey2)


class GeneratorOnCurve(Base):

    @drop_serialized
    def __init__(self, generator=None, raw=False, flags=ALL_FLAGS, ctx=None):
        Base.__init__(self, ctx, flags)
        if generator is not None:
            if raw:
                if not isinstance(generator, bytes):
                    raise TypeError('raw generator must be bytes')
                self.generator = self.deserialize(generator)
            else:
                if not isinstance(generator, ffi.CData):
                    raise TypeError('generator must be an internal object')
                if ffi.typeof(generator) is ffi.typeof('secp256k1_generator *'):
                  self.generator = generator
                elif ffi.typeof(generator) is ffi.typeof('secp256k1_generator'):
                  self.generator = ffi.new('secp256k1_generator *', generator)
                else:
                  raise Exception("Unknown generator type")
        else:
            self.generator = None
        self.bulletproof_generators = None
        self.bullteproof_generators_num = None

    def serialize(self):
        if self.serialized:
          return self.serialized
        assert self.generator, "No generator defined"

        _len = 33
        ret_buffer = ffi.new('unsigned char [%d]' % _len)

        serialized = lib.secp256k1_generator_serialize(
            self.ctx, ret_buffer, self.generator)
        assert serialized == 1 # well, useless assert, but let it be
        self.serialized = bytes(ffi.buffer(ret_buffer, _len))
        return bytes(ffi.buffer(ret_buffer, _len))

    def deserialize(self, generator_ser):
        if not len(generator_ser)==33:
            raise Exception("unknown generator size expected 33")

        generator = ffi.new('secp256k1_generator *')

        res = lib.secp256k1_generator_parse(
            self.ctx, generator, generator_ser )
        if not res:
            raise Exception("invalid generator")

        self.serialized = generator_ser
        self.generator = generator
        return generator

    def _from_point(self, point):
      pass #TODO

    @drop_serialized
    def _from_seed(self, seed):
      if not isinstance(seed, bytes) or not len(seed)==32:
            raise Exception("Seed should be 32 bytes")

      generator = ffi.new('secp256k1_generator *')

      res = lib.secp256k1_generator_generate(
            self.ctx, generator, seed )
      if not res:
            raise Exception("invalid generator")

      self.generator = generator
      return generator     

    @property
    def bulletproof_ready(self):
      return bool(self.bulletproof_generators)

    def initialise_bulletproof_generators(self, generators_num):
      if not isinstance(generators_num, int):
            raise Exception("Generators_num should be integer, got %s (%s)"%(type(generators_num), generators_num))

      bp_generators = lib.secp256k1_bulletproof_generators_create(self.ctx, self.generator, generators_num)
      
      if bp_generators==ffi.NULL:
            raise Exception("Initialisation has failed")

      self.bulletproof_generators = bp_generators
      self.bullteproof_generators_num = generators_num

    def __del__(self):
      if self.bulletproof_ready:
        lib.secp256k1_bulletproof_generators_destroy(self.ctx,  self.bulletproof_generators)
        self.bulletproof_generators = None
        self.bullteproof_generators_num = None


default_blinding_generator = GeneratorOnCurve(generator = lib.secp256k1_generator_const_g)
default_blinding_generator.initialise_bulletproof_generators(128)
default_value_generator = GeneratorOnCurve(generator = lib.secp256k1_generator_const_h)

class PedersenCommitment(Base):

    @drop_serialized
    def __init__(self, commitment=None, raw=False, flags=ALL_FLAGS, ctx=None, 
                       blinding_generator = default_blinding_generator,
                       value_generator = default_value_generator):
        Base.__init__(self, ctx, flags)
        if commitment is not None:
            if raw:
                if not isinstance(commitment, bytes):
                    raise TypeError('raw commmitment must be bytes')
                self.commitment = self.deserialize(commitment)
            else:
                if not isinstance(commitment, ffi.CData):
                    raise TypeError('commitment must be an internal object')
                assert ffi.typeof(commitment) is ffi.typeof('secp256k1_pedersen_commitment *')
                self.commitment = commitment
        else:
            self.commitment = None
        assert isinstance(blinding_generator, GeneratorOnCurve)
        assert isinstance(value_generator, GeneratorOnCurve)
        self.blinding_generator = blinding_generator
        self.value_generator = value_generator


    def serialize(self):
        if self.serialized:
          return self.serialized
        assert self.commitment, "No commitment key defined"

        _len = 33
        ret_buffer = ffi.new('unsigned char [%d]' % _len)

        serialized = lib.secp256k1_pedersen_commitment_serialize(
            self.ctx, ret_buffer, self.commitment)
        assert serialized == 1 # well, useless assert, but let it be
        self.serialized = bytes(ffi.buffer(ret_buffer, _len))
        return bytes(ffi.buffer(ret_buffer, _len))

    def deserialize(self, commitment_ser):
        if not len(commitment_ser)==33:
            raise Exception("unknown pedersen commitment size expected 33")

        commitment = ffi.new('secp256k1_pedersen_commitment *')

        res = lib.secp256k1_pedersen_commitment_parse(
            self.ctx, commitment, commitment_ser, )
        if not res:
            raise Exception("invalid pedersen commitment")
        self.serialized = commitment_ser
        self.commitment = commitment
        return commitment

    @drop_serialized
    def create(self, value, blinding_factor):
        if not isinstance( blinding_factor, bytes) or not len(blinding_factor)==32:
            raise TypeError('blinding_factor should be 32 bytes')
        self.blinding_factor = blinding_factor
        if not isinstance(value, int) or value<0 or value>2**64-1:
            raise TypeError('blinding_factor should be 32 bytes')
        self.value = value
        commitment = ffi.new('secp256k1_pedersen_commitment *')


        res = lib.secp256k1_pedersen_commit( self.ctx, 
        commitment, blinding_factor, value, 
        self.value_generator.generator,
        self.blinding_generator.generator) 
        if res:
          self.commitment=commitment
        return self.commitment


    def ready_to_sign(self):
      return self.blinding_factor and self.value


    def verify_sum(self, positive_commitments, negative_commitments):
        pcnt = len(positive_commitments)
        ncnt = len(negative_commitments)
        assert (pcnt and ncnt)
        positive_commitments_data = [commit.commitment for commit in positive_commitments]
        negative_commitments_data = [commit.commitment for commit in negative_commitments]

        for item in positive_commitments_data:
            assert ffi.typeof(item) is ffi.typeof('secp256k1_pedersen_commitment *')

        for item in negative_commitments_data:
            assert ffi.typeof(item) is ffi.typeof('secp256k1_pedersen_commitment *')

        res = lib.secp256k1_pedersen_verify_tally(
            self.ctx, positive_commitments_data, pcnt,
                      negative_commitments_data, ncnt)
        return bool(res)

    def to_public_key(self):
        """NOTE if value or blinding factor both are non-zero result of this function is not public key, cause it hasn't private key"""
        assert self.commitment

        point = ffi.new('secp256k1_point *')
        pubkey = ffi.new('secp256k1_pubkey *')

        lib.secp256k1_points_cast_pedersen_commitment_to_point(self.commitment, point)
        lib.secp256k1_points_cast_point_to_pubkey(point, pubkey)

        return PublicKey(pubkey, raw=False)

class RangeProof(Base):
  def __init__(self, proof=None, pedersen_commitment=None, additional_data=None, flags=ALL_FLAGS, ctx=None):
    Base.__init__(self, ctx, flags)
    if proof is not None:
      assert isinstance(proof, bytes)
    self.proof = proof
    if pedersen_commitment is not None:
      assert isinstance(pedersen_commitment, PedersenCommitment)
    self.pedersen_commitment = pedersen_commitment
    if additional_data is not None:
      assert isinstance(additional_data, bytes)
    self.additional_data = additional_data

  def verify(self, _range=(0,2**64-1) ):
    assert self.pedersen_commitment
    assert self.proof
    assert self.pedersen_commitment.value_generator == default_value_generator
    (ad,adl)= (self.additional_data, len(self.additional_data)) if self.additional_data else (ffi.cast("char *", 0), 0)
    min_value, max_value = ffi.new("uint64_t *"), ffi.new("uint64_t *")
    res = lib.secp256k1_rangeproof_verify(
            self.ctx, min_value, max_value,
            self.pedersen_commitment.commitment,
            self.proof, len(self.proof),
            ad, adl, self.pedersen_commitment.blinding_generator.generator)
    return res

  def rewind(self):
    pass #TODO

  def _sign(self, min_value=0, nonce=None, exp=0, concealed_bits=64):
    assert self.pedersen_commitment and self.pedersen_commitment.ready_to_sign()

    nonce = nonce if nonce else os.urandom(32)
    if not isinstance(nonce, bytes) or len(nonce)!=32:
      raise TypeError('nonce should be 32 bytes')

    _len = 5134
    proof_buffer = ffi.new('unsigned char [%d]' % _len)
    proof_buffer_len = ffi.new("size_t *")
    proof_buffer_len[0] = _len 

    (ad,adl)= (self.additional_data, len(self.additional_data)) if self.additional_data else (ffi.cast("char *", 0), 0)
    res = lib.secp256k1_rangeproof_sign( 
            self.ctx, proof_buffer, proof_buffer_len, min_value,
            self.pedersen_commitment.commitment, 
            self.pedersen_commitment.blinding_factor, 
            nonce, exp, concealed_bits,
            self.pedersen_commitment.value, 
            ffi.cast("char *", 0), 0,
            ad, adl, 
            self.pedersen_commitment.blinding_generator.generator)
    if not res:
      raise Exception("Cant generate rangeproof")
    self.proof = bytes(ffi.buffer(proof_buffer, proof_buffer_len[0])) 
    self.nonce = nonce
    return self.proof
            

  def info(self):
    exp, mantissa = [ffi.new("int *") for i in range(2)]
    min_value, max_value = [ffi.new("uint64_t *") for i in range(2)]
    res = lib.secp256k1_rangeproof_info(
              self.ctx, exp, mantissa,
              min_value, max_value, self.proof, len(self.proof)
              )
    return exp[0], mantissa[0], min_value[0], max_value[0]


class BulletProof(Base):
  scratch = {}


  def __init__(self, proof=None, pedersen_commitment=None, additional_data=None, flags=ALL_FLAGS, ctx=None):
    Base.__init__(self, ctx, flags)
    if proof is not None:
      assert isinstance(proof, bytes)
    self.proof = proof
    if pedersen_commitment is not None:
      assert isinstance(pedersen_commitment, PedersenCommitment)
      assert pedersen_commitment.blinding_generator.bulletproof_ready, "Generator is not bulletproof ready"
    self.pedersen_commitment = pedersen_commitment
    if additional_data is not None:
      assert isinstance(additional_data, bytes)
    self.additional_data = additional_data
    if not 'base' in self.scratch:
      self.scratch['base'] = lib.secp256k1_scratch_space_create(self.ctx, 1024**2)


  def verify(self, min_value=0, concealed_bits=64):
    assert self.pedersen_commitment
    assert self.proof
    (ad,adl)= (self.additional_data, len(self.additional_data)) if self.additional_data else (ffi.cast("char *", 0), 0)
    min_value = ffi.new("uint64_t *", min_value)

    res = lib.secp256k1_bulletproof_rangeproof_verify(
            self.ctx, self.scratch['base'], 
            self.pedersen_commitment.blinding_generator.bulletproof_generators,
            self.proof, len(self.proof), min_value, self.pedersen_commitment.commitment, 1,
            concealed_bits, 
            self.pedersen_commitment.value_generator.generator,
            ad, adl)
    return res

  @classmethod
  def batch_verify(cls, bullet_proofs, min_value=0, concealed_bits=64):
    assert len(bullet_proofs)
    for index, bp in enumerate(bullet_proofs):
      assert bp.proof, "No proof in %d element"
      assert bp.pedersen_commitment, "No pedersen commitment in %d element"
    n = len(bullet_proofs)

    _min_values = ffi.new("uint64_t []", [min_value]*n)
    min_values = ffi.cast("uint64_t * *", _min_values)
      

    proofs = ffi.new("unsigned char *[]", n)
    keep_alive_proofs = []
    commits = ffi.new("secp256k1_pedersen_commitment *[]", n)
    keep_alive_commits = []
    ads = ffi.new("unsigned char *[]", n)
    keep_alive_ads = []
    adls = ffi.new("size_t []", n)
    for i,p in enumerate(bullet_proofs):
      keep_alive_proofs.append(ffi.new("unsigned char[]",p.proof))
      proofs[i]=keep_alive_proofs[i]
      keep_alive_commits.append(p.pedersen_commitment.commitment)
      commits[i]=keep_alive_commits[i]
      keep_alive_ads.append(ffi.new("unsigned char[]",p.additional_data))
      ads[i]=keep_alive_ads[i]
      adls[i]=len(p.additional_data)

    example = bullet_proofs[0]

    res = lib.secp256k1_bulletproof_rangeproof_verify_multi(
            example.ctx, cls.scratch['base'], 
            example.pedersen_commitment.blinding_generator.bulletproof_generators,
            proofs, n, len(example.proof), min_values, commits, 1,
            concealed_bits, 
            example.pedersen_commitment.value_generator.generator,
            ads, adls)
    return res
    
   

  def rewind(self):
    pass #TODO

  def _sign(self, min_value=0, nonce=None, exp=0, concealed_bits=64):
    assert self.pedersen_commitment and self.pedersen_commitment.ready_to_sign()
    assert 0<concealed_bits<=64, "Concealed_bits should be  >0 and <=64"

    nonce = nonce if nonce else os.urandom(32)
    if not isinstance(nonce, bytes) or len(nonce)!=32:
      raise TypeError('nonce should be 32 bytes')

    _len = 5134
    proof_buffer = ffi.new('unsigned char [%d]' % _len)
    proof_buffer_len = ffi.new("size_t *")
    proof_buffer_len[0] = _len 
    blind = ffi.new('unsigned char[32]', self.pedersen_commitment.blinding_factor)
    blinds = ffi.new("unsigned char * *", blind)

    (ad,adl)= (self.additional_data, len(self.additional_data)) if self.additional_data else (ffi.cast("char *", 0), 0)
    res = lib.secp256k1_bulletproof_rangeproof_prove( 
            self.ctx, self.scratch['base'], 
            self.pedersen_commitment.blinding_generator.bulletproof_generators,
            proof_buffer, proof_buffer_len,
            ffi.NULL, ffi.NULL, ffi.NULL,
            [self.pedersen_commitment.value], [min_value],
            blinds, ffi.NULL, 1, 
            self.pedersen_commitment.value_generator.generator, 
            concealed_bits,
            nonce, ffi.NULL, 
            ad, adl,
            ffi.cast("char *", 0)
            ) 
    if not res:
      raise Exception("Cant generate rangeproof")
    self.proof = bytes(ffi.buffer(proof_buffer, proof_buffer_len[0])) 
    self.nonce = nonce
    return self.proof
            

        

class Point(Base):

    @drop_serialized
    def __init__(self, pointlike_object=None, raw_point = None, flags=FLAG_VERIFY, ctx=None):
        Base.__init__(self, ctx, flags)
        self.point = None
        if pointlike_object:
          _t = type(pointlike_object) 
          if not _t in [Point, PedersenCommitment, PublicKey, GeneratorOnCurve]:
            raise Exception("Unknown type of pointlike_object %s"%_t)
          self.point = ffi.new('secp256k1_point *')
          if _t==Point:
            self.point = pointlike_object.point
          elif _t==PublicKey:
            lib.secp256k1_points_cast_pubkey_to_point(self.ctx, pointlike_object.public_key, self.point)
          elif _t==PedersenCommitment:
            lib.secp256k1_points_cast_pedersen_commitment_to_point(pointlike_object.commitment, self.point)
          elif _t==GeneratorOnCurve:
            lib.secp256k1_points_cast_generator_to_point(pointlike_object.generator, self.point)
        if raw_point:
          self.deserialize(raw_point)

    def serialize(self):
        if self.serialized:
          return self.serialized
        assert self.point, "No point defined"
        ret_buffer = ffi.new('unsigned char [33]')
        serialized = lib.secp256k1_point_serialize(ret_buffer,self.point)
        assert serialized == 1
        self.serialized = bytes(ffi.buffer(ret_buffer, 33))
        return bytes(ffi.buffer(ret_buffer, 33))

    def deserialize(self, raw_point):
        self.point = ffi.new('secp256k1_point *')
        assert len(raw_point)==33
        res = lib.secp256k1_point_parse(self.point, raw_point)
        if not res:
          raise Exception("invalid point")
        self.serialized = raw_point
        return self.point

    def combine(self, points):
        """Add a number of points together."""
        assert len(points) > 0

        outpoint = ffi.new('secp256k1_point *')
        for item in points:
            assert ffi.typeof(item) is ffi.typeof('secp256k1_point *')

        res = lib.secp256k1_points_combine(
            outpoint, points, len(points))
        if not res:
            raise Exception('failed to combine public keys')

        self.point = outpoint
        return outpoint

    def __add__(self, point2):
        if isinstance(point2, Point):
            new_p= Point(ctx=self.ctx)
            new_p.combine([self.point, point2.point])
            return new_p
        else:
            raise TypeError("Cant add pubkey and %s"%point2.__class__)

    def __neg__(self):
        serialized=self.serialize()
        first_byte, remainder = serialized[:1], serialized[1:]
        first_byte = {b'\x81':b'\x80', b'\x80':b'\x81'}[first_byte]
        return Point(raw_point = first_byte+ remainder)

    def __sub__(self, point2):
        if isinstance(point2, Point):
            return self + (-point2)
        else:
            raise TypeError("Cant add point and %s"%pubkey2.__class__)

    def to_pedersen_commitment(self, flags=ALL_FLAGS, ctx=None, blinding_generator=default_blinding_generator):
        """Generate pedersen commitment r*G+0*H from r*G"""
        assert self.point
        commitment = ffi.new('secp256k1_pedersen_commitment *')
        lib.secp256k1_points_cast_point_to_pedersen_commitment(self.point, commitment)
        return PedersenCommitment(commitment, raw=False, flags=flags, ctx=ctx, blinding_generator=blinding_generator)

    def to_generator(self, flags=ALL_FLAGS, ctx=None):
        """Generate generator r*G"""
        assert self.point
        generator = ffi.new('secp256k1_generator *')
        lib.secp256k1_points_cast_point_to_generator(self.point, generator)
        return GeneratorOnCurve(generator, raw=False, flags=flags, ctx=ctx)

    def to_pubkey(self, flags=ALL_FLAGS, ctx=None):
        """Generate generator r*G"""
        assert self.point
        pubkey = ffi.new('secp256k1_pubkey *')
        lib.secp256k1_points_cast_point_to_pubkey(self.point, pubkey)
        return PublicKey(pubkey, raw=False, flags=flags, ctx=ctx )


def _int_to_bytes(n, length, endianess='big'):
    try:
        return n.to_bytes(length, endianess)
    except:
        h = '%x' % n
        s = ('0'*(len(h) % 2) + h).zfill(length*2).decode('hex')
        return s if endianess == 'big' else s[::-1]

def _bytes_to_int(bt, endianess='big'):
    try:
        return int.from_bytes(bt, endianess)
    except:
        bt = bt if endianess == 'big' else bt[::-1]
        bt = bytearray(bt)
        n=0
        for m in bt:
          n *= 256
          n+=int(m)
        return n
            


def _hash32(msg, raw, digest):
    if not raw:
        msg32 = digest(msg).digest()
    else:
        msg32 = msg
    if len(msg32) * 8 != 256:
        raise Exception("digest function must produce 256 bits")
    return msg32


def _gen_private_key():
    key = os.urandom(32)
    return key


def _tweak_public(inst, func, scalar):
    if not isinstance(scalar, bytes) or len(scalar) != 32:
        raise TypeError('scalar must be composed of 32 bytes')
    assert inst.public_key, "No public key defined."

    # Create a copy of the current public key.
    newpub = PublicKey(inst.serialize(), raw=True)

    res = func(inst.ctx, newpub.public_key, scalar)
    newpub.serialized = None
    if not res:
        raise Exception("Tweak is out of range")

    return newpub


def _tweak_private(inst, func, scalar):
    if not isinstance(scalar, bytes) or len(scalar) != 32:
        raise TypeError('scalar must be composed of 32 bytes')

    # Create a copy of the current private key.
    key = ffi.new('char [32]', inst.private_key)

    res = func(inst.ctx, key, scalar)
    if not res:
        raise Exception("Tweak is out of range")

    return bytes(ffi.buffer(key, 32))


def _main_cli(args, out, encoding='utf-8'):
    import binascii

    def show_public(public_key):
        rawp = public_key.serialize()
        out.write(u"Public key: {}\n".format(
            binascii.hexlify(rawp).decode(encoding)))

    def sign(funcname, params):
        raw = bytes(bytearray.fromhex(params.private_key))
        priv = PrivateKey(raw)
        func = getattr(priv, funcname)
        sig = func(params.message)
        return priv, sig

    if args.action == 'privkey':
        if args.private_key:
            rawkey = bytes(bytearray.fromhex(args.private_key))
        else:
            rawkey = None
        priv = PrivateKey(rawkey)
        raw = priv.private_key
        out.write(u"{}\n".format(binascii.hexlify(raw).decode(encoding)))
        if args.show_pubkey:
            show_public(priv.pubkey)

    elif args.action == 'sign':
        priv, sig_raw = sign('ecdsa_sign', args)
        sig = priv.ecdsa_serialize(sig_raw)
        out.write(u"{}\n".format(binascii.hexlify(sig).decode(encoding)))
        if args.show_pubkey:
            show_public(priv.pubkey)

    elif args.action == 'checksig':
        raw = bytes(bytearray.fromhex(args.public_key))
        sig = bytes(bytearray.fromhex(args.signature))
        pub = PublicKey(raw, raw=True)
        try:
            sig_raw = pub.ecdsa_deserialize(sig)
            good = pub.ecdsa_verify(args.message, sig_raw)
        except:
            good = False
        out.write(u"{}\n".format(good))
        return 0 if good else 1

    elif args.action == 'signrec':
        priv, sig = sign('ecdsa_sign_recoverable', args)
        sig, recid = priv.ecdsa_recoverable_serialize(sig)
        out.write(u"{} {}\n".format(binascii.hexlify(sig).decode(encoding), recid))
        if args.show_pubkey:
            show_public(priv.pubkey)

    elif args.action == 'recpub':
        empty = PublicKey(flags=ALL_FLAGS)
        sig_raw = bytes(bytearray.fromhex(args.signature))
        sig = empty.ecdsa_recoverable_deserialize(sig_raw, args.recid)
        pubkey = empty.ecdsa_recover(args.message, sig)
        show_public(PublicKey(pubkey))

    return 0


def _parse_cli():
    import sys
    from argparse import ArgumentParser

    py2 = sys.version_info.major == 2
    enc = sys.getfilesystemencoding()
    def bytes_input(s):
        return s if py2 else s.encode(enc)

    parser = ArgumentParser(prog="secp256k1")
    subparser = parser.add_subparsers(dest='action')

    genparser = subparser.add_parser('privkey')
    genparser.add_argument('-p', '--show-pubkey', action='store_true')
    genparser.add_argument('-k', '--private_key')

    sign = subparser.add_parser('sign')
    sign.add_argument('-k', '--private-key', required=True)
    sign.add_argument('-m', '--message', required=True, type=bytes_input)
    sign.add_argument('-p', '--show-pubkey', action='store_true')

    signrec = subparser.add_parser('signrec')
    signrec.add_argument('-k', '--private-key', required=True)
    signrec.add_argument('-m', '--message', required=True, type=bytes_input)
    signrec.add_argument('-p', '--show-pubkey', action='store_true')

    check = subparser.add_parser('checksig')
    check.add_argument('-p', '--public-key', required=True)
    check.add_argument('-m', '--message', required=True, type=bytes_input)
    check.add_argument('-s', '--signature', required=True)

    recpub = subparser.add_parser('recpub')
    recpub.add_argument('-m', '--message', required=True, type=bytes_input)
    recpub.add_argument('-i', '--recid', required=True, type=int)
    recpub.add_argument('-s', '--signature', required=True)

    return parser, enc


def main():
    import sys
    parser, enc = _parse_cli()
    args = parser.parse_args(sys.argv[1:])
    sys.exit(_main_cli(args, sys.stdout, enc))


if __name__ == '__main__':
    main()
