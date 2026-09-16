"""
EMV cryptography — key derivation and application cryptograms.

    from host.crypto import derive_udk, derive_session_key, verify_cryptogram

Needs pycryptodome for the DES primitive; nothing else here has dependencies.

A caution worth reading before trusting a result: the primitives and the
derivation steps are EMV Book 2 and are exercised by the test suite, but the
*data composition* for any particular scheme CVN is confidential and ships here
only as an editable profile. Validate against your target's own test vectors
before treating a verification result as evidence — `host.cli crypto selftest`
says exactly what has and has not been checked.
"""
from host.crypto.cryptogram import (  # noqa: F401
    CryptogramError,
    CryptogramProfile,
    arpc_method_1,
    arpc_method_2,
    available_profiles,
    build_data,
    compute_arqc,
    load_profile,
    resign,
    verify_cryptogram,
)
from host.crypto.des import (  # noqa: F401
    CryptoError,
    adjust_parity,
    des3_decrypt,
    des3_encrypt,
    has_odd_parity,
    mac_iso9797_alg3,
    xor,
)
from host.crypto.keys import (  # noqa: F401
    CSK,
    NONE,
    OPTION_A,
    OPTION_B,
    CardKeys,
    derive_session_key,
    derive_udk,
    load_imk,
    parse_key,
)

__all__ = [
    "CSK", "NONE", "OPTION_A", "OPTION_B", "CardKeys", "CryptoError",
    "CryptogramError", "CryptogramProfile", "adjust_parity", "arpc_method_1",
    "arpc_method_2", "available_profiles", "build_data", "compute_arqc",
    "derive_session_key", "derive_udk", "des3_decrypt", "des3_encrypt",
    "has_odd_parity", "load_imk", "load_profile", "mac_iso9797_alg3",
    "parse_key", "resign", "verify_cryptogram", "xor",
]
