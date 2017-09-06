import os
import sys
from collections import namedtuple
from itertools import combinations

from cffi import FFI, VerificationError

sys.path.append(os.path.abspath(os.path.dirname(__file__)))
from setup_support import has_system_lib, redirect, workdir, absolute

Source = namedtuple('Source', ('h', 'include'))


class Break(Exception):
    pass


def _mk_ffi(sources, name="_libsecp256k1", bundled=True, **kwargs):
    ffi = FFI()
    code = []
    if 'INCLUDE_DIR' in os.environ:
        kwargs['include_dirs'] = [absolute(os.environ['INCLUDE_DIR'])]
    if 'LIB_DIR' in os.environ:
        kwargs['library_dirs'] = [absolute(os.environ['LIB_DIR'])]
    for source in sources:
        with open(source.h, 'rt') as h:
            ffi.cdef(h.read())
        code.append(source.include)
    if bundled:
        code.append("#define PY_USE_BUNDLED")
    ffi.set_source(name, "\n".join(code), **kwargs)
    return ffi


_base = [Source(absolute("_cffi_build/secp256k1.h"), "#include <secp256k1.h>", )]

_modules = {
    'ecdh': Source(absolute("_cffi_build/secp256k1_ecdh.h"), "#include <secp256k1_ecdh.h>", ),
    'recovery': Source(absolute("_cffi_build/secp256k1_recovery.h"), "#include <secp256k1_recovery.h>", ),
    'schnorr': Source(absolute("_cffi_build/secp256k1_schnorr.h"), "#include <secp256k1_schnorr.h>", ),
}


ffi = None

#Allways use bundled version

if ffi is None:
    # Library is not installed - use bundled one
    print("Using bundled libsecp256k1")

    # By default use all modules
    ffi = _mk_ffi(_base + list(_modules.values()), libraries=['secp256k1'])
