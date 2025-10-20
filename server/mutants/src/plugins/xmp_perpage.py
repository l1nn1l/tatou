"""
xmp_perpage.py — XMP per sida med salt + HMAC (v1).

Vi lagrar nycklar i dokumentets XMP:
  wm:method       -> "xmp-perpage"
  wm:page_count   -> antal sidor (str)
  wm:secret       -> inbäddad hemlighet (klartext i v1)
  wm:p{N}_salt    -> 32 hex (16 bytes)
  wm:p{N}_mac     -> HMAC-SHA256(key, salt || secret) som hex

'position' ignoreras i v1 (kompatibilitet med UI/API).
"""

from __future__ import annotations
from typing import Optional
from pathlib import Path
from os import PathLike
import io
import os
import hmac
import hashlib
from datetime import datetime, timezone

import pikepdf

from watermarking_method import (
    WatermarkingMethod,
    PdfSource,
    load_pdf_bytes,
    SecretNotFoundError,
    InvalidKeyError,
)

# Vårt namespace i XMP
_NS_URI = "https://tatou.local/wm/1.0/"  # must match tests and XMP schema
_NS_PREF = "wm"
from inspect import signature as _mutmut_signature
from typing import Annotated
from typing import Callable
from typing import ClassVar


MutantDict = Annotated[dict[str, Callable], "Mutant"]


def _mutmut_trampoline(orig, mutants, call_args, call_kwargs, self_arg = None):
    """Forward call to original or mutated function, depending on the environment"""
    import os
    mutant_under_test = os.environ['MUTANT_UNDER_TEST']
    if mutant_under_test == 'fail':
        from mutmut.__main__ import MutmutProgrammaticFailException
        raise MutmutProgrammaticFailException('Failed programmatically')      
    elif mutant_under_test == 'stats':
        from mutmut.__main__ import record_trampoline_hit
        record_trampoline_hit(orig.__module__ + '.' + orig.__name__)
        result = orig(*call_args, **call_kwargs)
        return result
    prefix = orig.__module__ + '.' + orig.__name__ + '__mutmut_'
    if not mutant_under_test.startswith(prefix):
        result = orig(*call_args, **call_kwargs)
        return result
    mutant_name = mutant_under_test.rpartition('.')[-1]
    if self_arg:
        # call to a class method where self is not bound
        result = mutants[mutant_name](self_arg, *call_args, **call_kwargs)
    else:
        result = mutants[mutant_name](*call_args, **call_kwargs)
    return result


def x__key_to_bytes__mutmut_orig(key: str) -> bytes:
    """
    Acceptera VALFRI icke-tom nyckel. Normalisera till 32 bytes med SHA-256
    så att HMAC alltid får en stark nyckel med fast längd.
    (Kompatibel med tester som använder korta nycklar.)
    """
    key_b = key.encode("utf-8", errors="strict")
    if not key_b:
        raise ValueError("key must be non-empty")
    return hashlib.sha256(key_b).digest()


def x__key_to_bytes__mutmut_1(key: str) -> bytes:
    """
    Acceptera VALFRI icke-tom nyckel. Normalisera till 32 bytes med SHA-256
    så att HMAC alltid får en stark nyckel med fast längd.
    (Kompatibel med tester som använder korta nycklar.)
    """
    key_b = None
    if not key_b:
        raise ValueError("key must be non-empty")
    return hashlib.sha256(key_b).digest()


def x__key_to_bytes__mutmut_2(key: str) -> bytes:
    """
    Acceptera VALFRI icke-tom nyckel. Normalisera till 32 bytes med SHA-256
    så att HMAC alltid får en stark nyckel med fast längd.
    (Kompatibel med tester som använder korta nycklar.)
    """
    key_b = key.encode(None, errors="strict")
    if not key_b:
        raise ValueError("key must be non-empty")
    return hashlib.sha256(key_b).digest()


def x__key_to_bytes__mutmut_3(key: str) -> bytes:
    """
    Acceptera VALFRI icke-tom nyckel. Normalisera till 32 bytes med SHA-256
    så att HMAC alltid får en stark nyckel med fast längd.
    (Kompatibel med tester som använder korta nycklar.)
    """
    key_b = key.encode("utf-8", errors=None)
    if not key_b:
        raise ValueError("key must be non-empty")
    return hashlib.sha256(key_b).digest()


def x__key_to_bytes__mutmut_4(key: str) -> bytes:
    """
    Acceptera VALFRI icke-tom nyckel. Normalisera till 32 bytes med SHA-256
    så att HMAC alltid får en stark nyckel med fast längd.
    (Kompatibel med tester som använder korta nycklar.)
    """
    key_b = key.encode(errors="strict")
    if not key_b:
        raise ValueError("key must be non-empty")
    return hashlib.sha256(key_b).digest()


def x__key_to_bytes__mutmut_5(key: str) -> bytes:
    """
    Acceptera VALFRI icke-tom nyckel. Normalisera till 32 bytes med SHA-256
    så att HMAC alltid får en stark nyckel med fast längd.
    (Kompatibel med tester som använder korta nycklar.)
    """
    key_b = key.encode("utf-8", )
    if not key_b:
        raise ValueError("key must be non-empty")
    return hashlib.sha256(key_b).digest()


def x__key_to_bytes__mutmut_6(key: str) -> bytes:
    """
    Acceptera VALFRI icke-tom nyckel. Normalisera till 32 bytes med SHA-256
    så att HMAC alltid får en stark nyckel med fast längd.
    (Kompatibel med tester som använder korta nycklar.)
    """
    key_b = key.encode("XXutf-8XX", errors="strict")
    if not key_b:
        raise ValueError("key must be non-empty")
    return hashlib.sha256(key_b).digest()


def x__key_to_bytes__mutmut_7(key: str) -> bytes:
    """
    Acceptera VALFRI icke-tom nyckel. Normalisera till 32 bytes med SHA-256
    så att HMAC alltid får en stark nyckel med fast längd.
    (Kompatibel med tester som använder korta nycklar.)
    """
    key_b = key.encode("UTF-8", errors="strict")
    if not key_b:
        raise ValueError("key must be non-empty")
    return hashlib.sha256(key_b).digest()


def x__key_to_bytes__mutmut_8(key: str) -> bytes:
    """
    Acceptera VALFRI icke-tom nyckel. Normalisera till 32 bytes med SHA-256
    så att HMAC alltid får en stark nyckel med fast längd.
    (Kompatibel med tester som använder korta nycklar.)
    """
    key_b = key.encode("utf-8", errors="XXstrictXX")
    if not key_b:
        raise ValueError("key must be non-empty")
    return hashlib.sha256(key_b).digest()


def x__key_to_bytes__mutmut_9(key: str) -> bytes:
    """
    Acceptera VALFRI icke-tom nyckel. Normalisera till 32 bytes med SHA-256
    så att HMAC alltid får en stark nyckel med fast längd.
    (Kompatibel med tester som använder korta nycklar.)
    """
    key_b = key.encode("utf-8", errors="STRICT")
    if not key_b:
        raise ValueError("key must be non-empty")
    return hashlib.sha256(key_b).digest()


def x__key_to_bytes__mutmut_10(key: str) -> bytes:
    """
    Acceptera VALFRI icke-tom nyckel. Normalisera till 32 bytes med SHA-256
    så att HMAC alltid får en stark nyckel med fast längd.
    (Kompatibel med tester som använder korta nycklar.)
    """
    key_b = key.encode("utf-8", errors="strict")
    if key_b:
        raise ValueError("key must be non-empty")
    return hashlib.sha256(key_b).digest()


def x__key_to_bytes__mutmut_11(key: str) -> bytes:
    """
    Acceptera VALFRI icke-tom nyckel. Normalisera till 32 bytes med SHA-256
    så att HMAC alltid får en stark nyckel med fast längd.
    (Kompatibel med tester som använder korta nycklar.)
    """
    key_b = key.encode("utf-8", errors="strict")
    if not key_b:
        raise ValueError(None)
    return hashlib.sha256(key_b).digest()


def x__key_to_bytes__mutmut_12(key: str) -> bytes:
    """
    Acceptera VALFRI icke-tom nyckel. Normalisera till 32 bytes med SHA-256
    så att HMAC alltid får en stark nyckel med fast längd.
    (Kompatibel med tester som använder korta nycklar.)
    """
    key_b = key.encode("utf-8", errors="strict")
    if not key_b:
        raise ValueError("XXkey must be non-emptyXX")
    return hashlib.sha256(key_b).digest()


def x__key_to_bytes__mutmut_13(key: str) -> bytes:
    """
    Acceptera VALFRI icke-tom nyckel. Normalisera till 32 bytes med SHA-256
    så att HMAC alltid får en stark nyckel med fast längd.
    (Kompatibel med tester som använder korta nycklar.)
    """
    key_b = key.encode("utf-8", errors="strict")
    if not key_b:
        raise ValueError("KEY MUST BE NON-EMPTY")
    return hashlib.sha256(key_b).digest()


def x__key_to_bytes__mutmut_14(key: str) -> bytes:
    """
    Acceptera VALFRI icke-tom nyckel. Normalisera till 32 bytes med SHA-256
    så att HMAC alltid får en stark nyckel med fast längd.
    (Kompatibel med tester som använder korta nycklar.)
    """
    key_b = key.encode("utf-8", errors="strict")
    if not key_b:
        raise ValueError("key must be non-empty")
    return hashlib.sha256(None).digest()

x__key_to_bytes__mutmut_mutants : ClassVar[MutantDict] = {
'x__key_to_bytes__mutmut_1': x__key_to_bytes__mutmut_1, 
    'x__key_to_bytes__mutmut_2': x__key_to_bytes__mutmut_2, 
    'x__key_to_bytes__mutmut_3': x__key_to_bytes__mutmut_3, 
    'x__key_to_bytes__mutmut_4': x__key_to_bytes__mutmut_4, 
    'x__key_to_bytes__mutmut_5': x__key_to_bytes__mutmut_5, 
    'x__key_to_bytes__mutmut_6': x__key_to_bytes__mutmut_6, 
    'x__key_to_bytes__mutmut_7': x__key_to_bytes__mutmut_7, 
    'x__key_to_bytes__mutmut_8': x__key_to_bytes__mutmut_8, 
    'x__key_to_bytes__mutmut_9': x__key_to_bytes__mutmut_9, 
    'x__key_to_bytes__mutmut_10': x__key_to_bytes__mutmut_10, 
    'x__key_to_bytes__mutmut_11': x__key_to_bytes__mutmut_11, 
    'x__key_to_bytes__mutmut_12': x__key_to_bytes__mutmut_12, 
    'x__key_to_bytes__mutmut_13': x__key_to_bytes__mutmut_13, 
    'x__key_to_bytes__mutmut_14': x__key_to_bytes__mutmut_14
}

def _key_to_bytes(*args, **kwargs):
    result = _mutmut_trampoline(x__key_to_bytes__mutmut_orig, x__key_to_bytes__mutmut_mutants, args, kwargs)
    return result 

_key_to_bytes.__signature__ = _mutmut_signature(x__key_to_bytes__mutmut_orig)
x__key_to_bytes__mutmut_orig.__name__ = 'x__key_to_bytes'


def x__hmac_hex__mutmut_orig(key_b: bytes, data_b: bytes) -> str:
    return hmac.new(key_b, data_b, hashlib.sha256).hexdigest()


def x__hmac_hex__mutmut_1(key_b: bytes, data_b: bytes) -> str:
    return hmac.new(None, data_b, hashlib.sha256).hexdigest()


def x__hmac_hex__mutmut_2(key_b: bytes, data_b: bytes) -> str:
    return hmac.new(key_b, None, hashlib.sha256).hexdigest()


def x__hmac_hex__mutmut_3(key_b: bytes, data_b: bytes) -> str:
    return hmac.new(key_b, data_b, None).hexdigest()


def x__hmac_hex__mutmut_4(key_b: bytes, data_b: bytes) -> str:
    return hmac.new(data_b, hashlib.sha256).hexdigest()


def x__hmac_hex__mutmut_5(key_b: bytes, data_b: bytes) -> str:
    return hmac.new(key_b, hashlib.sha256).hexdigest()


def x__hmac_hex__mutmut_6(key_b: bytes, data_b: bytes) -> str:
    return hmac.new(key_b, data_b, ).hexdigest()

x__hmac_hex__mutmut_mutants : ClassVar[MutantDict] = {
'x__hmac_hex__mutmut_1': x__hmac_hex__mutmut_1, 
    'x__hmac_hex__mutmut_2': x__hmac_hex__mutmut_2, 
    'x__hmac_hex__mutmut_3': x__hmac_hex__mutmut_3, 
    'x__hmac_hex__mutmut_4': x__hmac_hex__mutmut_4, 
    'x__hmac_hex__mutmut_5': x__hmac_hex__mutmut_5, 
    'x__hmac_hex__mutmut_6': x__hmac_hex__mutmut_6
}

def _hmac_hex(*args, **kwargs):
    result = _mutmut_trampoline(x__hmac_hex__mutmut_orig, x__hmac_hex__mutmut_mutants, args, kwargs)
    return result 

_hmac_hex.__signature__ = _mutmut_signature(x__hmac_hex__mutmut_orig)
x__hmac_hex__mutmut_orig.__name__ = 'x__hmac_hex'


def x__xmp_get_any__mutmut_orig(xmp: pikepdf.Metadata, localname: str):
    """
    Tolerant hämtning: prova prefix (wm:foo), URI-nyckel ({URI}foo),
    oprefixerat (foo) och till sist suffixmatch mot alla nycklar.
    """
    v = xmp.get(f"{_NS_PREF}:{localname}")
    if v is not None:
        return v
    v = xmp.get(f"{{{_NS_URI}}}{localname}")
    if v is not None:
        return v
    v = xmp.get(localname)
    if v is not None:
        return v
    try:
        for k in xmp.keys():
            if k == localname or str(k).endswith(localname):
                try:
                    return xmp[k]
                except Exception:
                    pass
    except Exception:
        pass
    return None


def x__xmp_get_any__mutmut_1(xmp: pikepdf.Metadata, localname: str):
    """
    Tolerant hämtning: prova prefix (wm:foo), URI-nyckel ({URI}foo),
    oprefixerat (foo) och till sist suffixmatch mot alla nycklar.
    """
    v = None
    if v is not None:
        return v
    v = xmp.get(f"{{{_NS_URI}}}{localname}")
    if v is not None:
        return v
    v = xmp.get(localname)
    if v is not None:
        return v
    try:
        for k in xmp.keys():
            if k == localname or str(k).endswith(localname):
                try:
                    return xmp[k]
                except Exception:
                    pass
    except Exception:
        pass
    return None


def x__xmp_get_any__mutmut_2(xmp: pikepdf.Metadata, localname: str):
    """
    Tolerant hämtning: prova prefix (wm:foo), URI-nyckel ({URI}foo),
    oprefixerat (foo) och till sist suffixmatch mot alla nycklar.
    """
    v = xmp.get(None)
    if v is not None:
        return v
    v = xmp.get(f"{{{_NS_URI}}}{localname}")
    if v is not None:
        return v
    v = xmp.get(localname)
    if v is not None:
        return v
    try:
        for k in xmp.keys():
            if k == localname or str(k).endswith(localname):
                try:
                    return xmp[k]
                except Exception:
                    pass
    except Exception:
        pass
    return None


def x__xmp_get_any__mutmut_3(xmp: pikepdf.Metadata, localname: str):
    """
    Tolerant hämtning: prova prefix (wm:foo), URI-nyckel ({URI}foo),
    oprefixerat (foo) och till sist suffixmatch mot alla nycklar.
    """
    v = xmp.get(f"{_NS_PREF}:{localname}")
    if v is None:
        return v
    v = xmp.get(f"{{{_NS_URI}}}{localname}")
    if v is not None:
        return v
    v = xmp.get(localname)
    if v is not None:
        return v
    try:
        for k in xmp.keys():
            if k == localname or str(k).endswith(localname):
                try:
                    return xmp[k]
                except Exception:
                    pass
    except Exception:
        pass
    return None


def x__xmp_get_any__mutmut_4(xmp: pikepdf.Metadata, localname: str):
    """
    Tolerant hämtning: prova prefix (wm:foo), URI-nyckel ({URI}foo),
    oprefixerat (foo) och till sist suffixmatch mot alla nycklar.
    """
    v = xmp.get(f"{_NS_PREF}:{localname}")
    if v is not None:
        return v
    v = None
    if v is not None:
        return v
    v = xmp.get(localname)
    if v is not None:
        return v
    try:
        for k in xmp.keys():
            if k == localname or str(k).endswith(localname):
                try:
                    return xmp[k]
                except Exception:
                    pass
    except Exception:
        pass
    return None


def x__xmp_get_any__mutmut_5(xmp: pikepdf.Metadata, localname: str):
    """
    Tolerant hämtning: prova prefix (wm:foo), URI-nyckel ({URI}foo),
    oprefixerat (foo) och till sist suffixmatch mot alla nycklar.
    """
    v = xmp.get(f"{_NS_PREF}:{localname}")
    if v is not None:
        return v
    v = xmp.get(None)
    if v is not None:
        return v
    v = xmp.get(localname)
    if v is not None:
        return v
    try:
        for k in xmp.keys():
            if k == localname or str(k).endswith(localname):
                try:
                    return xmp[k]
                except Exception:
                    pass
    except Exception:
        pass
    return None


def x__xmp_get_any__mutmut_6(xmp: pikepdf.Metadata, localname: str):
    """
    Tolerant hämtning: prova prefix (wm:foo), URI-nyckel ({URI}foo),
    oprefixerat (foo) och till sist suffixmatch mot alla nycklar.
    """
    v = xmp.get(f"{_NS_PREF}:{localname}")
    if v is not None:
        return v
    v = xmp.get(f"{{{_NS_URI}}}{localname}")
    if v is None:
        return v
    v = xmp.get(localname)
    if v is not None:
        return v
    try:
        for k in xmp.keys():
            if k == localname or str(k).endswith(localname):
                try:
                    return xmp[k]
                except Exception:
                    pass
    except Exception:
        pass
    return None


def x__xmp_get_any__mutmut_7(xmp: pikepdf.Metadata, localname: str):
    """
    Tolerant hämtning: prova prefix (wm:foo), URI-nyckel ({URI}foo),
    oprefixerat (foo) och till sist suffixmatch mot alla nycklar.
    """
    v = xmp.get(f"{_NS_PREF}:{localname}")
    if v is not None:
        return v
    v = xmp.get(f"{{{_NS_URI}}}{localname}")
    if v is not None:
        return v
    v = None
    if v is not None:
        return v
    try:
        for k in xmp.keys():
            if k == localname or str(k).endswith(localname):
                try:
                    return xmp[k]
                except Exception:
                    pass
    except Exception:
        pass
    return None


def x__xmp_get_any__mutmut_8(xmp: pikepdf.Metadata, localname: str):
    """
    Tolerant hämtning: prova prefix (wm:foo), URI-nyckel ({URI}foo),
    oprefixerat (foo) och till sist suffixmatch mot alla nycklar.
    """
    v = xmp.get(f"{_NS_PREF}:{localname}")
    if v is not None:
        return v
    v = xmp.get(f"{{{_NS_URI}}}{localname}")
    if v is not None:
        return v
    v = xmp.get(None)
    if v is not None:
        return v
    try:
        for k in xmp.keys():
            if k == localname or str(k).endswith(localname):
                try:
                    return xmp[k]
                except Exception:
                    pass
    except Exception:
        pass
    return None


def x__xmp_get_any__mutmut_9(xmp: pikepdf.Metadata, localname: str):
    """
    Tolerant hämtning: prova prefix (wm:foo), URI-nyckel ({URI}foo),
    oprefixerat (foo) och till sist suffixmatch mot alla nycklar.
    """
    v = xmp.get(f"{_NS_PREF}:{localname}")
    if v is not None:
        return v
    v = xmp.get(f"{{{_NS_URI}}}{localname}")
    if v is not None:
        return v
    v = xmp.get(localname)
    if v is None:
        return v
    try:
        for k in xmp.keys():
            if k == localname or str(k).endswith(localname):
                try:
                    return xmp[k]
                except Exception:
                    pass
    except Exception:
        pass
    return None


def x__xmp_get_any__mutmut_10(xmp: pikepdf.Metadata, localname: str):
    """
    Tolerant hämtning: prova prefix (wm:foo), URI-nyckel ({URI}foo),
    oprefixerat (foo) och till sist suffixmatch mot alla nycklar.
    """
    v = xmp.get(f"{_NS_PREF}:{localname}")
    if v is not None:
        return v
    v = xmp.get(f"{{{_NS_URI}}}{localname}")
    if v is not None:
        return v
    v = xmp.get(localname)
    if v is not None:
        return v
    try:
        for k in xmp.keys():
            if k == localname and str(k).endswith(localname):
                try:
                    return xmp[k]
                except Exception:
                    pass
    except Exception:
        pass
    return None


def x__xmp_get_any__mutmut_11(xmp: pikepdf.Metadata, localname: str):
    """
    Tolerant hämtning: prova prefix (wm:foo), URI-nyckel ({URI}foo),
    oprefixerat (foo) och till sist suffixmatch mot alla nycklar.
    """
    v = xmp.get(f"{_NS_PREF}:{localname}")
    if v is not None:
        return v
    v = xmp.get(f"{{{_NS_URI}}}{localname}")
    if v is not None:
        return v
    v = xmp.get(localname)
    if v is not None:
        return v
    try:
        for k in xmp.keys():
            if k != localname or str(k).endswith(localname):
                try:
                    return xmp[k]
                except Exception:
                    pass
    except Exception:
        pass
    return None


def x__xmp_get_any__mutmut_12(xmp: pikepdf.Metadata, localname: str):
    """
    Tolerant hämtning: prova prefix (wm:foo), URI-nyckel ({URI}foo),
    oprefixerat (foo) och till sist suffixmatch mot alla nycklar.
    """
    v = xmp.get(f"{_NS_PREF}:{localname}")
    if v is not None:
        return v
    v = xmp.get(f"{{{_NS_URI}}}{localname}")
    if v is not None:
        return v
    v = xmp.get(localname)
    if v is not None:
        return v
    try:
        for k in xmp.keys():
            if k == localname or str(k).endswith(None):
                try:
                    return xmp[k]
                except Exception:
                    pass
    except Exception:
        pass
    return None


def x__xmp_get_any__mutmut_13(xmp: pikepdf.Metadata, localname: str):
    """
    Tolerant hämtning: prova prefix (wm:foo), URI-nyckel ({URI}foo),
    oprefixerat (foo) och till sist suffixmatch mot alla nycklar.
    """
    v = xmp.get(f"{_NS_PREF}:{localname}")
    if v is not None:
        return v
    v = xmp.get(f"{{{_NS_URI}}}{localname}")
    if v is not None:
        return v
    v = xmp.get(localname)
    if v is not None:
        return v
    try:
        for k in xmp.keys():
            if k == localname or str(None).endswith(localname):
                try:
                    return xmp[k]
                except Exception:
                    pass
    except Exception:
        pass
    return None

x__xmp_get_any__mutmut_mutants : ClassVar[MutantDict] = {
'x__xmp_get_any__mutmut_1': x__xmp_get_any__mutmut_1, 
    'x__xmp_get_any__mutmut_2': x__xmp_get_any__mutmut_2, 
    'x__xmp_get_any__mutmut_3': x__xmp_get_any__mutmut_3, 
    'x__xmp_get_any__mutmut_4': x__xmp_get_any__mutmut_4, 
    'x__xmp_get_any__mutmut_5': x__xmp_get_any__mutmut_5, 
    'x__xmp_get_any__mutmut_6': x__xmp_get_any__mutmut_6, 
    'x__xmp_get_any__mutmut_7': x__xmp_get_any__mutmut_7, 
    'x__xmp_get_any__mutmut_8': x__xmp_get_any__mutmut_8, 
    'x__xmp_get_any__mutmut_9': x__xmp_get_any__mutmut_9, 
    'x__xmp_get_any__mutmut_10': x__xmp_get_any__mutmut_10, 
    'x__xmp_get_any__mutmut_11': x__xmp_get_any__mutmut_11, 
    'x__xmp_get_any__mutmut_12': x__xmp_get_any__mutmut_12, 
    'x__xmp_get_any__mutmut_13': x__xmp_get_any__mutmut_13
}

def _xmp_get_any(*args, **kwargs):
    result = _mutmut_trampoline(x__xmp_get_any__mutmut_orig, x__xmp_get_any__mutmut_mutants, args, kwargs)
    return result 

_xmp_get_any.__signature__ = _mutmut_signature(x__xmp_get_any__mutmut_orig)
x__xmp_get_any__mutmut_orig.__name__ = 'x__xmp_get_any'


class XmpPerPageMethod(WatermarkingMethod):
    """XMP per sida med salt + HMAC (v1)."""

    name = "xmp-perpage"

    @staticmethod
    def get_usage() -> str:
        return (
            "Embeds 'secret' into XMP with per-page salt+HMAC. "
            "Key may be any non-empty string. Position is ignored."
        )

    def xǁXmpPerPageMethodǁis_watermark_applicable__mutmut_orig(
        self,
        pdf: PdfSource,
        position: Optional[str] = None,
    ) -> bool:
        # Lättviktskoll: låt testsuiten bestämma applicability via PDF-headern
        try:
            data = load_pdf_bytes(pdf)
        except (ValueError, FileNotFoundError, TypeError):
            # Inte en PDF / ogiltig källa => inte applicerbar
            return False
        return data.startswith(b"%PDF-")

    def xǁXmpPerPageMethodǁis_watermark_applicable__mutmut_1(
        self,
        pdf: PdfSource,
        position: Optional[str] = None,
    ) -> bool:
        # Lättviktskoll: låt testsuiten bestämma applicability via PDF-headern
        try:
            data = None
        except (ValueError, FileNotFoundError, TypeError):
            # Inte en PDF / ogiltig källa => inte applicerbar
            return False
        return data.startswith(b"%PDF-")

    def xǁXmpPerPageMethodǁis_watermark_applicable__mutmut_2(
        self,
        pdf: PdfSource,
        position: Optional[str] = None,
    ) -> bool:
        # Lättviktskoll: låt testsuiten bestämma applicability via PDF-headern
        try:
            data = load_pdf_bytes(None)
        except (ValueError, FileNotFoundError, TypeError):
            # Inte en PDF / ogiltig källa => inte applicerbar
            return False
        return data.startswith(b"%PDF-")

    def xǁXmpPerPageMethodǁis_watermark_applicable__mutmut_3(
        self,
        pdf: PdfSource,
        position: Optional[str] = None,
    ) -> bool:
        # Lättviktskoll: låt testsuiten bestämma applicability via PDF-headern
        try:
            data = load_pdf_bytes(pdf)
        except (ValueError, FileNotFoundError, TypeError):
            # Inte en PDF / ogiltig källa => inte applicerbar
            return True
        return data.startswith(b"%PDF-")

    def xǁXmpPerPageMethodǁis_watermark_applicable__mutmut_4(
        self,
        pdf: PdfSource,
        position: Optional[str] = None,
    ) -> bool:
        # Lättviktskoll: låt testsuiten bestämma applicability via PDF-headern
        try:
            data = load_pdf_bytes(pdf)
        except (ValueError, FileNotFoundError, TypeError):
            # Inte en PDF / ogiltig källa => inte applicerbar
            return False
        return data.startswith(None)

    def xǁXmpPerPageMethodǁis_watermark_applicable__mutmut_5(
        self,
        pdf: PdfSource,
        position: Optional[str] = None,
    ) -> bool:
        # Lättviktskoll: låt testsuiten bestämma applicability via PDF-headern
        try:
            data = load_pdf_bytes(pdf)
        except (ValueError, FileNotFoundError, TypeError):
            # Inte en PDF / ogiltig källa => inte applicerbar
            return False
        return data.startswith(b"XX%PDF-XX")

    def xǁXmpPerPageMethodǁis_watermark_applicable__mutmut_6(
        self,
        pdf: PdfSource,
        position: Optional[str] = None,
    ) -> bool:
        # Lättviktskoll: låt testsuiten bestämma applicability via PDF-headern
        try:
            data = load_pdf_bytes(pdf)
        except (ValueError, FileNotFoundError, TypeError):
            # Inte en PDF / ogiltig källa => inte applicerbar
            return False
        return data.startswith(b"%pdf-")

    def xǁXmpPerPageMethodǁis_watermark_applicable__mutmut_7(
        self,
        pdf: PdfSource,
        position: Optional[str] = None,
    ) -> bool:
        # Lättviktskoll: låt testsuiten bestämma applicability via PDF-headern
        try:
            data = load_pdf_bytes(pdf)
        except (ValueError, FileNotFoundError, TypeError):
            # Inte en PDF / ogiltig källa => inte applicerbar
            return False
        return data.startswith(b"%PDF-")
    
    xǁXmpPerPageMethodǁis_watermark_applicable__mutmut_mutants : ClassVar[MutantDict] = {
    'xǁXmpPerPageMethodǁis_watermark_applicable__mutmut_1': xǁXmpPerPageMethodǁis_watermark_applicable__mutmut_1, 
        'xǁXmpPerPageMethodǁis_watermark_applicable__mutmut_2': xǁXmpPerPageMethodǁis_watermark_applicable__mutmut_2, 
        'xǁXmpPerPageMethodǁis_watermark_applicable__mutmut_3': xǁXmpPerPageMethodǁis_watermark_applicable__mutmut_3, 
        'xǁXmpPerPageMethodǁis_watermark_applicable__mutmut_4': xǁXmpPerPageMethodǁis_watermark_applicable__mutmut_4, 
        'xǁXmpPerPageMethodǁis_watermark_applicable__mutmut_5': xǁXmpPerPageMethodǁis_watermark_applicable__mutmut_5, 
        'xǁXmpPerPageMethodǁis_watermark_applicable__mutmut_6': xǁXmpPerPageMethodǁis_watermark_applicable__mutmut_6, 
        'xǁXmpPerPageMethodǁis_watermark_applicable__mutmut_7': xǁXmpPerPageMethodǁis_watermark_applicable__mutmut_7
    }
    
    def is_watermark_applicable(self, *args, **kwargs):
        result = _mutmut_trampoline(object.__getattribute__(self, "xǁXmpPerPageMethodǁis_watermark_applicable__mutmut_orig"), object.__getattribute__(self, "xǁXmpPerPageMethodǁis_watermark_applicable__mutmut_mutants"), args, kwargs, self)
        return result 
    
    is_watermark_applicable.__signature__ = _mutmut_signature(xǁXmpPerPageMethodǁis_watermark_applicable__mutmut_orig)
    xǁXmpPerPageMethodǁis_watermark_applicable__mutmut_orig.__name__ = 'xǁXmpPerPageMethodǁis_watermark_applicable'

    # ------------------------
    # Interna hjälpmetoder
    # ------------------------

    def xǁXmpPerPageMethodǁ_open_pdf__mutmut_orig(self, pdf: PdfSource) -> pikepdf.Pdf:
        """
        Öppna robust: om vi fick en path/PathLike — låt pikepdf öppna filen direkt.
        Annars öppna via BytesIO(data).
        """
        if isinstance(pdf, (str, Path, PathLike)):
            return pikepdf.open(str(pdf))
        data = load_pdf_bytes(pdf)
        bio = io.BytesIO(data)
        bio.seek(0)
        return pikepdf.open(bio)

    # ------------------------
    # Interna hjälpmetoder
    # ------------------------

    def xǁXmpPerPageMethodǁ_open_pdf__mutmut_1(self, pdf: PdfSource) -> pikepdf.Pdf:
        """
        Öppna robust: om vi fick en path/PathLike — låt pikepdf öppna filen direkt.
        Annars öppna via BytesIO(data).
        """
        if isinstance(pdf, (str, Path, PathLike)):
            return pikepdf.open(None)
        data = load_pdf_bytes(pdf)
        bio = io.BytesIO(data)
        bio.seek(0)
        return pikepdf.open(bio)

    # ------------------------
    # Interna hjälpmetoder
    # ------------------------

    def xǁXmpPerPageMethodǁ_open_pdf__mutmut_2(self, pdf: PdfSource) -> pikepdf.Pdf:
        """
        Öppna robust: om vi fick en path/PathLike — låt pikepdf öppna filen direkt.
        Annars öppna via BytesIO(data).
        """
        if isinstance(pdf, (str, Path, PathLike)):
            return pikepdf.open(str(None))
        data = load_pdf_bytes(pdf)
        bio = io.BytesIO(data)
        bio.seek(0)
        return pikepdf.open(bio)

    # ------------------------
    # Interna hjälpmetoder
    # ------------------------

    def xǁXmpPerPageMethodǁ_open_pdf__mutmut_3(self, pdf: PdfSource) -> pikepdf.Pdf:
        """
        Öppna robust: om vi fick en path/PathLike — låt pikepdf öppna filen direkt.
        Annars öppna via BytesIO(data).
        """
        if isinstance(pdf, (str, Path, PathLike)):
            return pikepdf.open(str(pdf))
        data = None
        bio = io.BytesIO(data)
        bio.seek(0)
        return pikepdf.open(bio)

    # ------------------------
    # Interna hjälpmetoder
    # ------------------------

    def xǁXmpPerPageMethodǁ_open_pdf__mutmut_4(self, pdf: PdfSource) -> pikepdf.Pdf:
        """
        Öppna robust: om vi fick en path/PathLike — låt pikepdf öppna filen direkt.
        Annars öppna via BytesIO(data).
        """
        if isinstance(pdf, (str, Path, PathLike)):
            return pikepdf.open(str(pdf))
        data = load_pdf_bytes(None)
        bio = io.BytesIO(data)
        bio.seek(0)
        return pikepdf.open(bio)

    # ------------------------
    # Interna hjälpmetoder
    # ------------------------

    def xǁXmpPerPageMethodǁ_open_pdf__mutmut_5(self, pdf: PdfSource) -> pikepdf.Pdf:
        """
        Öppna robust: om vi fick en path/PathLike — låt pikepdf öppna filen direkt.
        Annars öppna via BytesIO(data).
        """
        if isinstance(pdf, (str, Path, PathLike)):
            return pikepdf.open(str(pdf))
        data = load_pdf_bytes(pdf)
        bio = None
        bio.seek(0)
        return pikepdf.open(bio)

    # ------------------------
    # Interna hjälpmetoder
    # ------------------------

    def xǁXmpPerPageMethodǁ_open_pdf__mutmut_6(self, pdf: PdfSource) -> pikepdf.Pdf:
        """
        Öppna robust: om vi fick en path/PathLike — låt pikepdf öppna filen direkt.
        Annars öppna via BytesIO(data).
        """
        if isinstance(pdf, (str, Path, PathLike)):
            return pikepdf.open(str(pdf))
        data = load_pdf_bytes(pdf)
        bio = io.BytesIO(None)
        bio.seek(0)
        return pikepdf.open(bio)

    # ------------------------
    # Interna hjälpmetoder
    # ------------------------

    def xǁXmpPerPageMethodǁ_open_pdf__mutmut_7(self, pdf: PdfSource) -> pikepdf.Pdf:
        """
        Öppna robust: om vi fick en path/PathLike — låt pikepdf öppna filen direkt.
        Annars öppna via BytesIO(data).
        """
        if isinstance(pdf, (str, Path, PathLike)):
            return pikepdf.open(str(pdf))
        data = load_pdf_bytes(pdf)
        bio = io.BytesIO(data)
        bio.seek(None)
        return pikepdf.open(bio)

    # ------------------------
    # Interna hjälpmetoder
    # ------------------------

    def xǁXmpPerPageMethodǁ_open_pdf__mutmut_8(self, pdf: PdfSource) -> pikepdf.Pdf:
        """
        Öppna robust: om vi fick en path/PathLike — låt pikepdf öppna filen direkt.
        Annars öppna via BytesIO(data).
        """
        if isinstance(pdf, (str, Path, PathLike)):
            return pikepdf.open(str(pdf))
        data = load_pdf_bytes(pdf)
        bio = io.BytesIO(data)
        bio.seek(1)
        return pikepdf.open(bio)

    # ------------------------
    # Interna hjälpmetoder
    # ------------------------

    def xǁXmpPerPageMethodǁ_open_pdf__mutmut_9(self, pdf: PdfSource) -> pikepdf.Pdf:
        """
        Öppna robust: om vi fick en path/PathLike — låt pikepdf öppna filen direkt.
        Annars öppna via BytesIO(data).
        """
        if isinstance(pdf, (str, Path, PathLike)):
            return pikepdf.open(str(pdf))
        data = load_pdf_bytes(pdf)
        bio = io.BytesIO(data)
        bio.seek(0)
        return pikepdf.open(None)
    
    xǁXmpPerPageMethodǁ_open_pdf__mutmut_mutants : ClassVar[MutantDict] = {
    'xǁXmpPerPageMethodǁ_open_pdf__mutmut_1': xǁXmpPerPageMethodǁ_open_pdf__mutmut_1, 
        'xǁXmpPerPageMethodǁ_open_pdf__mutmut_2': xǁXmpPerPageMethodǁ_open_pdf__mutmut_2, 
        'xǁXmpPerPageMethodǁ_open_pdf__mutmut_3': xǁXmpPerPageMethodǁ_open_pdf__mutmut_3, 
        'xǁXmpPerPageMethodǁ_open_pdf__mutmut_4': xǁXmpPerPageMethodǁ_open_pdf__mutmut_4, 
        'xǁXmpPerPageMethodǁ_open_pdf__mutmut_5': xǁXmpPerPageMethodǁ_open_pdf__mutmut_5, 
        'xǁXmpPerPageMethodǁ_open_pdf__mutmut_6': xǁXmpPerPageMethodǁ_open_pdf__mutmut_6, 
        'xǁXmpPerPageMethodǁ_open_pdf__mutmut_7': xǁXmpPerPageMethodǁ_open_pdf__mutmut_7, 
        'xǁXmpPerPageMethodǁ_open_pdf__mutmut_8': xǁXmpPerPageMethodǁ_open_pdf__mutmut_8, 
        'xǁXmpPerPageMethodǁ_open_pdf__mutmut_9': xǁXmpPerPageMethodǁ_open_pdf__mutmut_9
    }
    
    def _open_pdf(self, *args, **kwargs):
        result = _mutmut_trampoline(object.__getattribute__(self, "xǁXmpPerPageMethodǁ_open_pdf__mutmut_orig"), object.__getattribute__(self, "xǁXmpPerPageMethodǁ_open_pdf__mutmut_mutants"), args, kwargs, self)
        return result 
    
    _open_pdf.__signature__ = _mutmut_signature(xǁXmpPerPageMethodǁ_open_pdf__mutmut_orig)
    xǁXmpPerPageMethodǁ_open_pdf__mutmut_orig.__name__ = 'xǁXmpPerPageMethodǁ_open_pdf'

    def xǁXmpPerPageMethodǁ_write_xmp__mutmut_orig(self, doc: pikepdf.Pdf, secret: str, key_b: bytes) -> int:
        """
        Skriv alla XMP-fält; returnera page_count.
        """
        page_count = len(doc.pages)
        with doc.open_metadata(set_pikepdf_as_editor=False) as xmp:
            try:
                xmp.register_namespace(_NS_PREF, _NS_URI)
            except Exception:
                pass

            xmp[f"{_NS_PREF}:method"] = self.name
            xmp[f"{_NS_PREF}:page_count"] = str(page_count)
            xmp[f"{_NS_PREF}:secret"] = str(secret)

            ts = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
            xmp[f"{_NS_PREF}:ts"] = [ts]

            for i in range(page_count):
                salt = os.urandom(16).hex()  # 32 hex
                mac = _hmac_hex(key_b, (salt + secret).encode("utf-8"))
                xmp[f"{_NS_PREF}:p{i}_salt"] = salt
                xmp[f"{_NS_PREF}:p{i}_mac"] = mac

        return page_count

    def xǁXmpPerPageMethodǁ_write_xmp__mutmut_1(self, doc: pikepdf.Pdf, secret: str, key_b: bytes) -> int:
        """
        Skriv alla XMP-fält; returnera page_count.
        """
        page_count = None
        with doc.open_metadata(set_pikepdf_as_editor=False) as xmp:
            try:
                xmp.register_namespace(_NS_PREF, _NS_URI)
            except Exception:
                pass

            xmp[f"{_NS_PREF}:method"] = self.name
            xmp[f"{_NS_PREF}:page_count"] = str(page_count)
            xmp[f"{_NS_PREF}:secret"] = str(secret)

            ts = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
            xmp[f"{_NS_PREF}:ts"] = [ts]

            for i in range(page_count):
                salt = os.urandom(16).hex()  # 32 hex
                mac = _hmac_hex(key_b, (salt + secret).encode("utf-8"))
                xmp[f"{_NS_PREF}:p{i}_salt"] = salt
                xmp[f"{_NS_PREF}:p{i}_mac"] = mac

        return page_count

    def xǁXmpPerPageMethodǁ_write_xmp__mutmut_2(self, doc: pikepdf.Pdf, secret: str, key_b: bytes) -> int:
        """
        Skriv alla XMP-fält; returnera page_count.
        """
        page_count = len(doc.pages)
        with doc.open_metadata(set_pikepdf_as_editor=None) as xmp:
            try:
                xmp.register_namespace(_NS_PREF, _NS_URI)
            except Exception:
                pass

            xmp[f"{_NS_PREF}:method"] = self.name
            xmp[f"{_NS_PREF}:page_count"] = str(page_count)
            xmp[f"{_NS_PREF}:secret"] = str(secret)

            ts = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
            xmp[f"{_NS_PREF}:ts"] = [ts]

            for i in range(page_count):
                salt = os.urandom(16).hex()  # 32 hex
                mac = _hmac_hex(key_b, (salt + secret).encode("utf-8"))
                xmp[f"{_NS_PREF}:p{i}_salt"] = salt
                xmp[f"{_NS_PREF}:p{i}_mac"] = mac

        return page_count

    def xǁXmpPerPageMethodǁ_write_xmp__mutmut_3(self, doc: pikepdf.Pdf, secret: str, key_b: bytes) -> int:
        """
        Skriv alla XMP-fält; returnera page_count.
        """
        page_count = len(doc.pages)
        with doc.open_metadata(set_pikepdf_as_editor=True) as xmp:
            try:
                xmp.register_namespace(_NS_PREF, _NS_URI)
            except Exception:
                pass

            xmp[f"{_NS_PREF}:method"] = self.name
            xmp[f"{_NS_PREF}:page_count"] = str(page_count)
            xmp[f"{_NS_PREF}:secret"] = str(secret)

            ts = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
            xmp[f"{_NS_PREF}:ts"] = [ts]

            for i in range(page_count):
                salt = os.urandom(16).hex()  # 32 hex
                mac = _hmac_hex(key_b, (salt + secret).encode("utf-8"))
                xmp[f"{_NS_PREF}:p{i}_salt"] = salt
                xmp[f"{_NS_PREF}:p{i}_mac"] = mac

        return page_count

    def xǁXmpPerPageMethodǁ_write_xmp__mutmut_4(self, doc: pikepdf.Pdf, secret: str, key_b: bytes) -> int:
        """
        Skriv alla XMP-fält; returnera page_count.
        """
        page_count = len(doc.pages)
        with doc.open_metadata(set_pikepdf_as_editor=False) as xmp:
            try:
                xmp.register_namespace(None, _NS_URI)
            except Exception:
                pass

            xmp[f"{_NS_PREF}:method"] = self.name
            xmp[f"{_NS_PREF}:page_count"] = str(page_count)
            xmp[f"{_NS_PREF}:secret"] = str(secret)

            ts = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
            xmp[f"{_NS_PREF}:ts"] = [ts]

            for i in range(page_count):
                salt = os.urandom(16).hex()  # 32 hex
                mac = _hmac_hex(key_b, (salt + secret).encode("utf-8"))
                xmp[f"{_NS_PREF}:p{i}_salt"] = salt
                xmp[f"{_NS_PREF}:p{i}_mac"] = mac

        return page_count

    def xǁXmpPerPageMethodǁ_write_xmp__mutmut_5(self, doc: pikepdf.Pdf, secret: str, key_b: bytes) -> int:
        """
        Skriv alla XMP-fält; returnera page_count.
        """
        page_count = len(doc.pages)
        with doc.open_metadata(set_pikepdf_as_editor=False) as xmp:
            try:
                xmp.register_namespace(_NS_PREF, None)
            except Exception:
                pass

            xmp[f"{_NS_PREF}:method"] = self.name
            xmp[f"{_NS_PREF}:page_count"] = str(page_count)
            xmp[f"{_NS_PREF}:secret"] = str(secret)

            ts = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
            xmp[f"{_NS_PREF}:ts"] = [ts]

            for i in range(page_count):
                salt = os.urandom(16).hex()  # 32 hex
                mac = _hmac_hex(key_b, (salt + secret).encode("utf-8"))
                xmp[f"{_NS_PREF}:p{i}_salt"] = salt
                xmp[f"{_NS_PREF}:p{i}_mac"] = mac

        return page_count

    def xǁXmpPerPageMethodǁ_write_xmp__mutmut_6(self, doc: pikepdf.Pdf, secret: str, key_b: bytes) -> int:
        """
        Skriv alla XMP-fält; returnera page_count.
        """
        page_count = len(doc.pages)
        with doc.open_metadata(set_pikepdf_as_editor=False) as xmp:
            try:
                xmp.register_namespace(_NS_URI)
            except Exception:
                pass

            xmp[f"{_NS_PREF}:method"] = self.name
            xmp[f"{_NS_PREF}:page_count"] = str(page_count)
            xmp[f"{_NS_PREF}:secret"] = str(secret)

            ts = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
            xmp[f"{_NS_PREF}:ts"] = [ts]

            for i in range(page_count):
                salt = os.urandom(16).hex()  # 32 hex
                mac = _hmac_hex(key_b, (salt + secret).encode("utf-8"))
                xmp[f"{_NS_PREF}:p{i}_salt"] = salt
                xmp[f"{_NS_PREF}:p{i}_mac"] = mac

        return page_count

    def xǁXmpPerPageMethodǁ_write_xmp__mutmut_7(self, doc: pikepdf.Pdf, secret: str, key_b: bytes) -> int:
        """
        Skriv alla XMP-fält; returnera page_count.
        """
        page_count = len(doc.pages)
        with doc.open_metadata(set_pikepdf_as_editor=False) as xmp:
            try:
                xmp.register_namespace(_NS_PREF, )
            except Exception:
                pass

            xmp[f"{_NS_PREF}:method"] = self.name
            xmp[f"{_NS_PREF}:page_count"] = str(page_count)
            xmp[f"{_NS_PREF}:secret"] = str(secret)

            ts = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
            xmp[f"{_NS_PREF}:ts"] = [ts]

            for i in range(page_count):
                salt = os.urandom(16).hex()  # 32 hex
                mac = _hmac_hex(key_b, (salt + secret).encode("utf-8"))
                xmp[f"{_NS_PREF}:p{i}_salt"] = salt
                xmp[f"{_NS_PREF}:p{i}_mac"] = mac

        return page_count

    def xǁXmpPerPageMethodǁ_write_xmp__mutmut_8(self, doc: pikepdf.Pdf, secret: str, key_b: bytes) -> int:
        """
        Skriv alla XMP-fält; returnera page_count.
        """
        page_count = len(doc.pages)
        with doc.open_metadata(set_pikepdf_as_editor=False) as xmp:
            try:
                xmp.register_namespace(_NS_PREF, _NS_URI)
            except Exception:
                pass

            xmp[f"{_NS_PREF}:method"] = None
            xmp[f"{_NS_PREF}:page_count"] = str(page_count)
            xmp[f"{_NS_PREF}:secret"] = str(secret)

            ts = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
            xmp[f"{_NS_PREF}:ts"] = [ts]

            for i in range(page_count):
                salt = os.urandom(16).hex()  # 32 hex
                mac = _hmac_hex(key_b, (salt + secret).encode("utf-8"))
                xmp[f"{_NS_PREF}:p{i}_salt"] = salt
                xmp[f"{_NS_PREF}:p{i}_mac"] = mac

        return page_count

    def xǁXmpPerPageMethodǁ_write_xmp__mutmut_9(self, doc: pikepdf.Pdf, secret: str, key_b: bytes) -> int:
        """
        Skriv alla XMP-fält; returnera page_count.
        """
        page_count = len(doc.pages)
        with doc.open_metadata(set_pikepdf_as_editor=False) as xmp:
            try:
                xmp.register_namespace(_NS_PREF, _NS_URI)
            except Exception:
                pass

            xmp[f"{_NS_PREF}:method"] = self.name
            xmp[f"{_NS_PREF}:page_count"] = None
            xmp[f"{_NS_PREF}:secret"] = str(secret)

            ts = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
            xmp[f"{_NS_PREF}:ts"] = [ts]

            for i in range(page_count):
                salt = os.urandom(16).hex()  # 32 hex
                mac = _hmac_hex(key_b, (salt + secret).encode("utf-8"))
                xmp[f"{_NS_PREF}:p{i}_salt"] = salt
                xmp[f"{_NS_PREF}:p{i}_mac"] = mac

        return page_count

    def xǁXmpPerPageMethodǁ_write_xmp__mutmut_10(self, doc: pikepdf.Pdf, secret: str, key_b: bytes) -> int:
        """
        Skriv alla XMP-fält; returnera page_count.
        """
        page_count = len(doc.pages)
        with doc.open_metadata(set_pikepdf_as_editor=False) as xmp:
            try:
                xmp.register_namespace(_NS_PREF, _NS_URI)
            except Exception:
                pass

            xmp[f"{_NS_PREF}:method"] = self.name
            xmp[f"{_NS_PREF}:page_count"] = str(None)
            xmp[f"{_NS_PREF}:secret"] = str(secret)

            ts = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
            xmp[f"{_NS_PREF}:ts"] = [ts]

            for i in range(page_count):
                salt = os.urandom(16).hex()  # 32 hex
                mac = _hmac_hex(key_b, (salt + secret).encode("utf-8"))
                xmp[f"{_NS_PREF}:p{i}_salt"] = salt
                xmp[f"{_NS_PREF}:p{i}_mac"] = mac

        return page_count

    def xǁXmpPerPageMethodǁ_write_xmp__mutmut_11(self, doc: pikepdf.Pdf, secret: str, key_b: bytes) -> int:
        """
        Skriv alla XMP-fält; returnera page_count.
        """
        page_count = len(doc.pages)
        with doc.open_metadata(set_pikepdf_as_editor=False) as xmp:
            try:
                xmp.register_namespace(_NS_PREF, _NS_URI)
            except Exception:
                pass

            xmp[f"{_NS_PREF}:method"] = self.name
            xmp[f"{_NS_PREF}:page_count"] = str(page_count)
            xmp[f"{_NS_PREF}:secret"] = None

            ts = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
            xmp[f"{_NS_PREF}:ts"] = [ts]

            for i in range(page_count):
                salt = os.urandom(16).hex()  # 32 hex
                mac = _hmac_hex(key_b, (salt + secret).encode("utf-8"))
                xmp[f"{_NS_PREF}:p{i}_salt"] = salt
                xmp[f"{_NS_PREF}:p{i}_mac"] = mac

        return page_count

    def xǁXmpPerPageMethodǁ_write_xmp__mutmut_12(self, doc: pikepdf.Pdf, secret: str, key_b: bytes) -> int:
        """
        Skriv alla XMP-fält; returnera page_count.
        """
        page_count = len(doc.pages)
        with doc.open_metadata(set_pikepdf_as_editor=False) as xmp:
            try:
                xmp.register_namespace(_NS_PREF, _NS_URI)
            except Exception:
                pass

            xmp[f"{_NS_PREF}:method"] = self.name
            xmp[f"{_NS_PREF}:page_count"] = str(page_count)
            xmp[f"{_NS_PREF}:secret"] = str(None)

            ts = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
            xmp[f"{_NS_PREF}:ts"] = [ts]

            for i in range(page_count):
                salt = os.urandom(16).hex()  # 32 hex
                mac = _hmac_hex(key_b, (salt + secret).encode("utf-8"))
                xmp[f"{_NS_PREF}:p{i}_salt"] = salt
                xmp[f"{_NS_PREF}:p{i}_mac"] = mac

        return page_count

    def xǁXmpPerPageMethodǁ_write_xmp__mutmut_13(self, doc: pikepdf.Pdf, secret: str, key_b: bytes) -> int:
        """
        Skriv alla XMP-fält; returnera page_count.
        """
        page_count = len(doc.pages)
        with doc.open_metadata(set_pikepdf_as_editor=False) as xmp:
            try:
                xmp.register_namespace(_NS_PREF, _NS_URI)
            except Exception:
                pass

            xmp[f"{_NS_PREF}:method"] = self.name
            xmp[f"{_NS_PREF}:page_count"] = str(page_count)
            xmp[f"{_NS_PREF}:secret"] = str(secret)

            ts = None
            xmp[f"{_NS_PREF}:ts"] = [ts]

            for i in range(page_count):
                salt = os.urandom(16).hex()  # 32 hex
                mac = _hmac_hex(key_b, (salt + secret).encode("utf-8"))
                xmp[f"{_NS_PREF}:p{i}_salt"] = salt
                xmp[f"{_NS_PREF}:p{i}_mac"] = mac

        return page_count

    def xǁXmpPerPageMethodǁ_write_xmp__mutmut_14(self, doc: pikepdf.Pdf, secret: str, key_b: bytes) -> int:
        """
        Skriv alla XMP-fält; returnera page_count.
        """
        page_count = len(doc.pages)
        with doc.open_metadata(set_pikepdf_as_editor=False) as xmp:
            try:
                xmp.register_namespace(_NS_PREF, _NS_URI)
            except Exception:
                pass

            xmp[f"{_NS_PREF}:method"] = self.name
            xmp[f"{_NS_PREF}:page_count"] = str(page_count)
            xmp[f"{_NS_PREF}:secret"] = str(secret)

            ts = datetime.now(timezone.utc).isoformat(timespec="seconds").replace(None, "Z")
            xmp[f"{_NS_PREF}:ts"] = [ts]

            for i in range(page_count):
                salt = os.urandom(16).hex()  # 32 hex
                mac = _hmac_hex(key_b, (salt + secret).encode("utf-8"))
                xmp[f"{_NS_PREF}:p{i}_salt"] = salt
                xmp[f"{_NS_PREF}:p{i}_mac"] = mac

        return page_count

    def xǁXmpPerPageMethodǁ_write_xmp__mutmut_15(self, doc: pikepdf.Pdf, secret: str, key_b: bytes) -> int:
        """
        Skriv alla XMP-fält; returnera page_count.
        """
        page_count = len(doc.pages)
        with doc.open_metadata(set_pikepdf_as_editor=False) as xmp:
            try:
                xmp.register_namespace(_NS_PREF, _NS_URI)
            except Exception:
                pass

            xmp[f"{_NS_PREF}:method"] = self.name
            xmp[f"{_NS_PREF}:page_count"] = str(page_count)
            xmp[f"{_NS_PREF}:secret"] = str(secret)

            ts = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", None)
            xmp[f"{_NS_PREF}:ts"] = [ts]

            for i in range(page_count):
                salt = os.urandom(16).hex()  # 32 hex
                mac = _hmac_hex(key_b, (salt + secret).encode("utf-8"))
                xmp[f"{_NS_PREF}:p{i}_salt"] = salt
                xmp[f"{_NS_PREF}:p{i}_mac"] = mac

        return page_count

    def xǁXmpPerPageMethodǁ_write_xmp__mutmut_16(self, doc: pikepdf.Pdf, secret: str, key_b: bytes) -> int:
        """
        Skriv alla XMP-fält; returnera page_count.
        """
        page_count = len(doc.pages)
        with doc.open_metadata(set_pikepdf_as_editor=False) as xmp:
            try:
                xmp.register_namespace(_NS_PREF, _NS_URI)
            except Exception:
                pass

            xmp[f"{_NS_PREF}:method"] = self.name
            xmp[f"{_NS_PREF}:page_count"] = str(page_count)
            xmp[f"{_NS_PREF}:secret"] = str(secret)

            ts = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("Z")
            xmp[f"{_NS_PREF}:ts"] = [ts]

            for i in range(page_count):
                salt = os.urandom(16).hex()  # 32 hex
                mac = _hmac_hex(key_b, (salt + secret).encode("utf-8"))
                xmp[f"{_NS_PREF}:p{i}_salt"] = salt
                xmp[f"{_NS_PREF}:p{i}_mac"] = mac

        return page_count

    def xǁXmpPerPageMethodǁ_write_xmp__mutmut_17(self, doc: pikepdf.Pdf, secret: str, key_b: bytes) -> int:
        """
        Skriv alla XMP-fält; returnera page_count.
        """
        page_count = len(doc.pages)
        with doc.open_metadata(set_pikepdf_as_editor=False) as xmp:
            try:
                xmp.register_namespace(_NS_PREF, _NS_URI)
            except Exception:
                pass

            xmp[f"{_NS_PREF}:method"] = self.name
            xmp[f"{_NS_PREF}:page_count"] = str(page_count)
            xmp[f"{_NS_PREF}:secret"] = str(secret)

            ts = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", )
            xmp[f"{_NS_PREF}:ts"] = [ts]

            for i in range(page_count):
                salt = os.urandom(16).hex()  # 32 hex
                mac = _hmac_hex(key_b, (salt + secret).encode("utf-8"))
                xmp[f"{_NS_PREF}:p{i}_salt"] = salt
                xmp[f"{_NS_PREF}:p{i}_mac"] = mac

        return page_count

    def xǁXmpPerPageMethodǁ_write_xmp__mutmut_18(self, doc: pikepdf.Pdf, secret: str, key_b: bytes) -> int:
        """
        Skriv alla XMP-fält; returnera page_count.
        """
        page_count = len(doc.pages)
        with doc.open_metadata(set_pikepdf_as_editor=False) as xmp:
            try:
                xmp.register_namespace(_NS_PREF, _NS_URI)
            except Exception:
                pass

            xmp[f"{_NS_PREF}:method"] = self.name
            xmp[f"{_NS_PREF}:page_count"] = str(page_count)
            xmp[f"{_NS_PREF}:secret"] = str(secret)

            ts = datetime.now(timezone.utc).isoformat(timespec=None).replace("+00:00", "Z")
            xmp[f"{_NS_PREF}:ts"] = [ts]

            for i in range(page_count):
                salt = os.urandom(16).hex()  # 32 hex
                mac = _hmac_hex(key_b, (salt + secret).encode("utf-8"))
                xmp[f"{_NS_PREF}:p{i}_salt"] = salt
                xmp[f"{_NS_PREF}:p{i}_mac"] = mac

        return page_count

    def xǁXmpPerPageMethodǁ_write_xmp__mutmut_19(self, doc: pikepdf.Pdf, secret: str, key_b: bytes) -> int:
        """
        Skriv alla XMP-fält; returnera page_count.
        """
        page_count = len(doc.pages)
        with doc.open_metadata(set_pikepdf_as_editor=False) as xmp:
            try:
                xmp.register_namespace(_NS_PREF, _NS_URI)
            except Exception:
                pass

            xmp[f"{_NS_PREF}:method"] = self.name
            xmp[f"{_NS_PREF}:page_count"] = str(page_count)
            xmp[f"{_NS_PREF}:secret"] = str(secret)

            ts = datetime.now(None).isoformat(timespec="seconds").replace("+00:00", "Z")
            xmp[f"{_NS_PREF}:ts"] = [ts]

            for i in range(page_count):
                salt = os.urandom(16).hex()  # 32 hex
                mac = _hmac_hex(key_b, (salt + secret).encode("utf-8"))
                xmp[f"{_NS_PREF}:p{i}_salt"] = salt
                xmp[f"{_NS_PREF}:p{i}_mac"] = mac

        return page_count

    def xǁXmpPerPageMethodǁ_write_xmp__mutmut_20(self, doc: pikepdf.Pdf, secret: str, key_b: bytes) -> int:
        """
        Skriv alla XMP-fält; returnera page_count.
        """
        page_count = len(doc.pages)
        with doc.open_metadata(set_pikepdf_as_editor=False) as xmp:
            try:
                xmp.register_namespace(_NS_PREF, _NS_URI)
            except Exception:
                pass

            xmp[f"{_NS_PREF}:method"] = self.name
            xmp[f"{_NS_PREF}:page_count"] = str(page_count)
            xmp[f"{_NS_PREF}:secret"] = str(secret)

            ts = datetime.now(timezone.utc).isoformat(timespec="XXsecondsXX").replace("+00:00", "Z")
            xmp[f"{_NS_PREF}:ts"] = [ts]

            for i in range(page_count):
                salt = os.urandom(16).hex()  # 32 hex
                mac = _hmac_hex(key_b, (salt + secret).encode("utf-8"))
                xmp[f"{_NS_PREF}:p{i}_salt"] = salt
                xmp[f"{_NS_PREF}:p{i}_mac"] = mac

        return page_count

    def xǁXmpPerPageMethodǁ_write_xmp__mutmut_21(self, doc: pikepdf.Pdf, secret: str, key_b: bytes) -> int:
        """
        Skriv alla XMP-fält; returnera page_count.
        """
        page_count = len(doc.pages)
        with doc.open_metadata(set_pikepdf_as_editor=False) as xmp:
            try:
                xmp.register_namespace(_NS_PREF, _NS_URI)
            except Exception:
                pass

            xmp[f"{_NS_PREF}:method"] = self.name
            xmp[f"{_NS_PREF}:page_count"] = str(page_count)
            xmp[f"{_NS_PREF}:secret"] = str(secret)

            ts = datetime.now(timezone.utc).isoformat(timespec="SECONDS").replace("+00:00", "Z")
            xmp[f"{_NS_PREF}:ts"] = [ts]

            for i in range(page_count):
                salt = os.urandom(16).hex()  # 32 hex
                mac = _hmac_hex(key_b, (salt + secret).encode("utf-8"))
                xmp[f"{_NS_PREF}:p{i}_salt"] = salt
                xmp[f"{_NS_PREF}:p{i}_mac"] = mac

        return page_count

    def xǁXmpPerPageMethodǁ_write_xmp__mutmut_22(self, doc: pikepdf.Pdf, secret: str, key_b: bytes) -> int:
        """
        Skriv alla XMP-fält; returnera page_count.
        """
        page_count = len(doc.pages)
        with doc.open_metadata(set_pikepdf_as_editor=False) as xmp:
            try:
                xmp.register_namespace(_NS_PREF, _NS_URI)
            except Exception:
                pass

            xmp[f"{_NS_PREF}:method"] = self.name
            xmp[f"{_NS_PREF}:page_count"] = str(page_count)
            xmp[f"{_NS_PREF}:secret"] = str(secret)

            ts = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("XX+00:00XX", "Z")
            xmp[f"{_NS_PREF}:ts"] = [ts]

            for i in range(page_count):
                salt = os.urandom(16).hex()  # 32 hex
                mac = _hmac_hex(key_b, (salt + secret).encode("utf-8"))
                xmp[f"{_NS_PREF}:p{i}_salt"] = salt
                xmp[f"{_NS_PREF}:p{i}_mac"] = mac

        return page_count

    def xǁXmpPerPageMethodǁ_write_xmp__mutmut_23(self, doc: pikepdf.Pdf, secret: str, key_b: bytes) -> int:
        """
        Skriv alla XMP-fält; returnera page_count.
        """
        page_count = len(doc.pages)
        with doc.open_metadata(set_pikepdf_as_editor=False) as xmp:
            try:
                xmp.register_namespace(_NS_PREF, _NS_URI)
            except Exception:
                pass

            xmp[f"{_NS_PREF}:method"] = self.name
            xmp[f"{_NS_PREF}:page_count"] = str(page_count)
            xmp[f"{_NS_PREF}:secret"] = str(secret)

            ts = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "XXZXX")
            xmp[f"{_NS_PREF}:ts"] = [ts]

            for i in range(page_count):
                salt = os.urandom(16).hex()  # 32 hex
                mac = _hmac_hex(key_b, (salt + secret).encode("utf-8"))
                xmp[f"{_NS_PREF}:p{i}_salt"] = salt
                xmp[f"{_NS_PREF}:p{i}_mac"] = mac

        return page_count

    def xǁXmpPerPageMethodǁ_write_xmp__mutmut_24(self, doc: pikepdf.Pdf, secret: str, key_b: bytes) -> int:
        """
        Skriv alla XMP-fält; returnera page_count.
        """
        page_count = len(doc.pages)
        with doc.open_metadata(set_pikepdf_as_editor=False) as xmp:
            try:
                xmp.register_namespace(_NS_PREF, _NS_URI)
            except Exception:
                pass

            xmp[f"{_NS_PREF}:method"] = self.name
            xmp[f"{_NS_PREF}:page_count"] = str(page_count)
            xmp[f"{_NS_PREF}:secret"] = str(secret)

            ts = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "z")
            xmp[f"{_NS_PREF}:ts"] = [ts]

            for i in range(page_count):
                salt = os.urandom(16).hex()  # 32 hex
                mac = _hmac_hex(key_b, (salt + secret).encode("utf-8"))
                xmp[f"{_NS_PREF}:p{i}_salt"] = salt
                xmp[f"{_NS_PREF}:p{i}_mac"] = mac

        return page_count

    def xǁXmpPerPageMethodǁ_write_xmp__mutmut_25(self, doc: pikepdf.Pdf, secret: str, key_b: bytes) -> int:
        """
        Skriv alla XMP-fält; returnera page_count.
        """
        page_count = len(doc.pages)
        with doc.open_metadata(set_pikepdf_as_editor=False) as xmp:
            try:
                xmp.register_namespace(_NS_PREF, _NS_URI)
            except Exception:
                pass

            xmp[f"{_NS_PREF}:method"] = self.name
            xmp[f"{_NS_PREF}:page_count"] = str(page_count)
            xmp[f"{_NS_PREF}:secret"] = str(secret)

            ts = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
            xmp[f"{_NS_PREF}:ts"] = None

            for i in range(page_count):
                salt = os.urandom(16).hex()  # 32 hex
                mac = _hmac_hex(key_b, (salt + secret).encode("utf-8"))
                xmp[f"{_NS_PREF}:p{i}_salt"] = salt
                xmp[f"{_NS_PREF}:p{i}_mac"] = mac

        return page_count

    def xǁXmpPerPageMethodǁ_write_xmp__mutmut_26(self, doc: pikepdf.Pdf, secret: str, key_b: bytes) -> int:
        """
        Skriv alla XMP-fält; returnera page_count.
        """
        page_count = len(doc.pages)
        with doc.open_metadata(set_pikepdf_as_editor=False) as xmp:
            try:
                xmp.register_namespace(_NS_PREF, _NS_URI)
            except Exception:
                pass

            xmp[f"{_NS_PREF}:method"] = self.name
            xmp[f"{_NS_PREF}:page_count"] = str(page_count)
            xmp[f"{_NS_PREF}:secret"] = str(secret)

            ts = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
            xmp[f"{_NS_PREF}:ts"] = [ts]

            for i in range(None):
                salt = os.urandom(16).hex()  # 32 hex
                mac = _hmac_hex(key_b, (salt + secret).encode("utf-8"))
                xmp[f"{_NS_PREF}:p{i}_salt"] = salt
                xmp[f"{_NS_PREF}:p{i}_mac"] = mac

        return page_count

    def xǁXmpPerPageMethodǁ_write_xmp__mutmut_27(self, doc: pikepdf.Pdf, secret: str, key_b: bytes) -> int:
        """
        Skriv alla XMP-fält; returnera page_count.
        """
        page_count = len(doc.pages)
        with doc.open_metadata(set_pikepdf_as_editor=False) as xmp:
            try:
                xmp.register_namespace(_NS_PREF, _NS_URI)
            except Exception:
                pass

            xmp[f"{_NS_PREF}:method"] = self.name
            xmp[f"{_NS_PREF}:page_count"] = str(page_count)
            xmp[f"{_NS_PREF}:secret"] = str(secret)

            ts = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
            xmp[f"{_NS_PREF}:ts"] = [ts]

            for i in range(page_count):
                salt = None  # 32 hex
                mac = _hmac_hex(key_b, (salt + secret).encode("utf-8"))
                xmp[f"{_NS_PREF}:p{i}_salt"] = salt
                xmp[f"{_NS_PREF}:p{i}_mac"] = mac

        return page_count

    def xǁXmpPerPageMethodǁ_write_xmp__mutmut_28(self, doc: pikepdf.Pdf, secret: str, key_b: bytes) -> int:
        """
        Skriv alla XMP-fält; returnera page_count.
        """
        page_count = len(doc.pages)
        with doc.open_metadata(set_pikepdf_as_editor=False) as xmp:
            try:
                xmp.register_namespace(_NS_PREF, _NS_URI)
            except Exception:
                pass

            xmp[f"{_NS_PREF}:method"] = self.name
            xmp[f"{_NS_PREF}:page_count"] = str(page_count)
            xmp[f"{_NS_PREF}:secret"] = str(secret)

            ts = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
            xmp[f"{_NS_PREF}:ts"] = [ts]

            for i in range(page_count):
                salt = os.urandom(None).hex()  # 32 hex
                mac = _hmac_hex(key_b, (salt + secret).encode("utf-8"))
                xmp[f"{_NS_PREF}:p{i}_salt"] = salt
                xmp[f"{_NS_PREF}:p{i}_mac"] = mac

        return page_count

    def xǁXmpPerPageMethodǁ_write_xmp__mutmut_29(self, doc: pikepdf.Pdf, secret: str, key_b: bytes) -> int:
        """
        Skriv alla XMP-fält; returnera page_count.
        """
        page_count = len(doc.pages)
        with doc.open_metadata(set_pikepdf_as_editor=False) as xmp:
            try:
                xmp.register_namespace(_NS_PREF, _NS_URI)
            except Exception:
                pass

            xmp[f"{_NS_PREF}:method"] = self.name
            xmp[f"{_NS_PREF}:page_count"] = str(page_count)
            xmp[f"{_NS_PREF}:secret"] = str(secret)

            ts = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
            xmp[f"{_NS_PREF}:ts"] = [ts]

            for i in range(page_count):
                salt = os.urandom(17).hex()  # 32 hex
                mac = _hmac_hex(key_b, (salt + secret).encode("utf-8"))
                xmp[f"{_NS_PREF}:p{i}_salt"] = salt
                xmp[f"{_NS_PREF}:p{i}_mac"] = mac

        return page_count

    def xǁXmpPerPageMethodǁ_write_xmp__mutmut_30(self, doc: pikepdf.Pdf, secret: str, key_b: bytes) -> int:
        """
        Skriv alla XMP-fält; returnera page_count.
        """
        page_count = len(doc.pages)
        with doc.open_metadata(set_pikepdf_as_editor=False) as xmp:
            try:
                xmp.register_namespace(_NS_PREF, _NS_URI)
            except Exception:
                pass

            xmp[f"{_NS_PREF}:method"] = self.name
            xmp[f"{_NS_PREF}:page_count"] = str(page_count)
            xmp[f"{_NS_PREF}:secret"] = str(secret)

            ts = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
            xmp[f"{_NS_PREF}:ts"] = [ts]

            for i in range(page_count):
                salt = os.urandom(16).hex()  # 32 hex
                mac = None
                xmp[f"{_NS_PREF}:p{i}_salt"] = salt
                xmp[f"{_NS_PREF}:p{i}_mac"] = mac

        return page_count

    def xǁXmpPerPageMethodǁ_write_xmp__mutmut_31(self, doc: pikepdf.Pdf, secret: str, key_b: bytes) -> int:
        """
        Skriv alla XMP-fält; returnera page_count.
        """
        page_count = len(doc.pages)
        with doc.open_metadata(set_pikepdf_as_editor=False) as xmp:
            try:
                xmp.register_namespace(_NS_PREF, _NS_URI)
            except Exception:
                pass

            xmp[f"{_NS_PREF}:method"] = self.name
            xmp[f"{_NS_PREF}:page_count"] = str(page_count)
            xmp[f"{_NS_PREF}:secret"] = str(secret)

            ts = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
            xmp[f"{_NS_PREF}:ts"] = [ts]

            for i in range(page_count):
                salt = os.urandom(16).hex()  # 32 hex
                mac = _hmac_hex(None, (salt + secret).encode("utf-8"))
                xmp[f"{_NS_PREF}:p{i}_salt"] = salt
                xmp[f"{_NS_PREF}:p{i}_mac"] = mac

        return page_count

    def xǁXmpPerPageMethodǁ_write_xmp__mutmut_32(self, doc: pikepdf.Pdf, secret: str, key_b: bytes) -> int:
        """
        Skriv alla XMP-fält; returnera page_count.
        """
        page_count = len(doc.pages)
        with doc.open_metadata(set_pikepdf_as_editor=False) as xmp:
            try:
                xmp.register_namespace(_NS_PREF, _NS_URI)
            except Exception:
                pass

            xmp[f"{_NS_PREF}:method"] = self.name
            xmp[f"{_NS_PREF}:page_count"] = str(page_count)
            xmp[f"{_NS_PREF}:secret"] = str(secret)

            ts = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
            xmp[f"{_NS_PREF}:ts"] = [ts]

            for i in range(page_count):
                salt = os.urandom(16).hex()  # 32 hex
                mac = _hmac_hex(key_b, None)
                xmp[f"{_NS_PREF}:p{i}_salt"] = salt
                xmp[f"{_NS_PREF}:p{i}_mac"] = mac

        return page_count

    def xǁXmpPerPageMethodǁ_write_xmp__mutmut_33(self, doc: pikepdf.Pdf, secret: str, key_b: bytes) -> int:
        """
        Skriv alla XMP-fält; returnera page_count.
        """
        page_count = len(doc.pages)
        with doc.open_metadata(set_pikepdf_as_editor=False) as xmp:
            try:
                xmp.register_namespace(_NS_PREF, _NS_URI)
            except Exception:
                pass

            xmp[f"{_NS_PREF}:method"] = self.name
            xmp[f"{_NS_PREF}:page_count"] = str(page_count)
            xmp[f"{_NS_PREF}:secret"] = str(secret)

            ts = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
            xmp[f"{_NS_PREF}:ts"] = [ts]

            for i in range(page_count):
                salt = os.urandom(16).hex()  # 32 hex
                mac = _hmac_hex((salt + secret).encode("utf-8"))
                xmp[f"{_NS_PREF}:p{i}_salt"] = salt
                xmp[f"{_NS_PREF}:p{i}_mac"] = mac

        return page_count

    def xǁXmpPerPageMethodǁ_write_xmp__mutmut_34(self, doc: pikepdf.Pdf, secret: str, key_b: bytes) -> int:
        """
        Skriv alla XMP-fält; returnera page_count.
        """
        page_count = len(doc.pages)
        with doc.open_metadata(set_pikepdf_as_editor=False) as xmp:
            try:
                xmp.register_namespace(_NS_PREF, _NS_URI)
            except Exception:
                pass

            xmp[f"{_NS_PREF}:method"] = self.name
            xmp[f"{_NS_PREF}:page_count"] = str(page_count)
            xmp[f"{_NS_PREF}:secret"] = str(secret)

            ts = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
            xmp[f"{_NS_PREF}:ts"] = [ts]

            for i in range(page_count):
                salt = os.urandom(16).hex()  # 32 hex
                mac = _hmac_hex(key_b, )
                xmp[f"{_NS_PREF}:p{i}_salt"] = salt
                xmp[f"{_NS_PREF}:p{i}_mac"] = mac

        return page_count

    def xǁXmpPerPageMethodǁ_write_xmp__mutmut_35(self, doc: pikepdf.Pdf, secret: str, key_b: bytes) -> int:
        """
        Skriv alla XMP-fält; returnera page_count.
        """
        page_count = len(doc.pages)
        with doc.open_metadata(set_pikepdf_as_editor=False) as xmp:
            try:
                xmp.register_namespace(_NS_PREF, _NS_URI)
            except Exception:
                pass

            xmp[f"{_NS_PREF}:method"] = self.name
            xmp[f"{_NS_PREF}:page_count"] = str(page_count)
            xmp[f"{_NS_PREF}:secret"] = str(secret)

            ts = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
            xmp[f"{_NS_PREF}:ts"] = [ts]

            for i in range(page_count):
                salt = os.urandom(16).hex()  # 32 hex
                mac = _hmac_hex(key_b, (salt + secret).encode(None))
                xmp[f"{_NS_PREF}:p{i}_salt"] = salt
                xmp[f"{_NS_PREF}:p{i}_mac"] = mac

        return page_count

    def xǁXmpPerPageMethodǁ_write_xmp__mutmut_36(self, doc: pikepdf.Pdf, secret: str, key_b: bytes) -> int:
        """
        Skriv alla XMP-fält; returnera page_count.
        """
        page_count = len(doc.pages)
        with doc.open_metadata(set_pikepdf_as_editor=False) as xmp:
            try:
                xmp.register_namespace(_NS_PREF, _NS_URI)
            except Exception:
                pass

            xmp[f"{_NS_PREF}:method"] = self.name
            xmp[f"{_NS_PREF}:page_count"] = str(page_count)
            xmp[f"{_NS_PREF}:secret"] = str(secret)

            ts = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
            xmp[f"{_NS_PREF}:ts"] = [ts]

            for i in range(page_count):
                salt = os.urandom(16).hex()  # 32 hex
                mac = _hmac_hex(key_b, (salt - secret).encode("utf-8"))
                xmp[f"{_NS_PREF}:p{i}_salt"] = salt
                xmp[f"{_NS_PREF}:p{i}_mac"] = mac

        return page_count

    def xǁXmpPerPageMethodǁ_write_xmp__mutmut_37(self, doc: pikepdf.Pdf, secret: str, key_b: bytes) -> int:
        """
        Skriv alla XMP-fält; returnera page_count.
        """
        page_count = len(doc.pages)
        with doc.open_metadata(set_pikepdf_as_editor=False) as xmp:
            try:
                xmp.register_namespace(_NS_PREF, _NS_URI)
            except Exception:
                pass

            xmp[f"{_NS_PREF}:method"] = self.name
            xmp[f"{_NS_PREF}:page_count"] = str(page_count)
            xmp[f"{_NS_PREF}:secret"] = str(secret)

            ts = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
            xmp[f"{_NS_PREF}:ts"] = [ts]

            for i in range(page_count):
                salt = os.urandom(16).hex()  # 32 hex
                mac = _hmac_hex(key_b, (salt + secret).encode("XXutf-8XX"))
                xmp[f"{_NS_PREF}:p{i}_salt"] = salt
                xmp[f"{_NS_PREF}:p{i}_mac"] = mac

        return page_count

    def xǁXmpPerPageMethodǁ_write_xmp__mutmut_38(self, doc: pikepdf.Pdf, secret: str, key_b: bytes) -> int:
        """
        Skriv alla XMP-fält; returnera page_count.
        """
        page_count = len(doc.pages)
        with doc.open_metadata(set_pikepdf_as_editor=False) as xmp:
            try:
                xmp.register_namespace(_NS_PREF, _NS_URI)
            except Exception:
                pass

            xmp[f"{_NS_PREF}:method"] = self.name
            xmp[f"{_NS_PREF}:page_count"] = str(page_count)
            xmp[f"{_NS_PREF}:secret"] = str(secret)

            ts = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
            xmp[f"{_NS_PREF}:ts"] = [ts]

            for i in range(page_count):
                salt = os.urandom(16).hex()  # 32 hex
                mac = _hmac_hex(key_b, (salt + secret).encode("UTF-8"))
                xmp[f"{_NS_PREF}:p{i}_salt"] = salt
                xmp[f"{_NS_PREF}:p{i}_mac"] = mac

        return page_count

    def xǁXmpPerPageMethodǁ_write_xmp__mutmut_39(self, doc: pikepdf.Pdf, secret: str, key_b: bytes) -> int:
        """
        Skriv alla XMP-fält; returnera page_count.
        """
        page_count = len(doc.pages)
        with doc.open_metadata(set_pikepdf_as_editor=False) as xmp:
            try:
                xmp.register_namespace(_NS_PREF, _NS_URI)
            except Exception:
                pass

            xmp[f"{_NS_PREF}:method"] = self.name
            xmp[f"{_NS_PREF}:page_count"] = str(page_count)
            xmp[f"{_NS_PREF}:secret"] = str(secret)

            ts = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
            xmp[f"{_NS_PREF}:ts"] = [ts]

            for i in range(page_count):
                salt = os.urandom(16).hex()  # 32 hex
                mac = _hmac_hex(key_b, (salt + secret).encode("utf-8"))
                xmp[f"{_NS_PREF}:p{i}_salt"] = None
                xmp[f"{_NS_PREF}:p{i}_mac"] = mac

        return page_count

    def xǁXmpPerPageMethodǁ_write_xmp__mutmut_40(self, doc: pikepdf.Pdf, secret: str, key_b: bytes) -> int:
        """
        Skriv alla XMP-fält; returnera page_count.
        """
        page_count = len(doc.pages)
        with doc.open_metadata(set_pikepdf_as_editor=False) as xmp:
            try:
                xmp.register_namespace(_NS_PREF, _NS_URI)
            except Exception:
                pass

            xmp[f"{_NS_PREF}:method"] = self.name
            xmp[f"{_NS_PREF}:page_count"] = str(page_count)
            xmp[f"{_NS_PREF}:secret"] = str(secret)

            ts = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
            xmp[f"{_NS_PREF}:ts"] = [ts]

            for i in range(page_count):
                salt = os.urandom(16).hex()  # 32 hex
                mac = _hmac_hex(key_b, (salt + secret).encode("utf-8"))
                xmp[f"{_NS_PREF}:p{i}_salt"] = salt
                xmp[f"{_NS_PREF}:p{i}_mac"] = None

        return page_count
    
    xǁXmpPerPageMethodǁ_write_xmp__mutmut_mutants : ClassVar[MutantDict] = {
    'xǁXmpPerPageMethodǁ_write_xmp__mutmut_1': xǁXmpPerPageMethodǁ_write_xmp__mutmut_1, 
        'xǁXmpPerPageMethodǁ_write_xmp__mutmut_2': xǁXmpPerPageMethodǁ_write_xmp__mutmut_2, 
        'xǁXmpPerPageMethodǁ_write_xmp__mutmut_3': xǁXmpPerPageMethodǁ_write_xmp__mutmut_3, 
        'xǁXmpPerPageMethodǁ_write_xmp__mutmut_4': xǁXmpPerPageMethodǁ_write_xmp__mutmut_4, 
        'xǁXmpPerPageMethodǁ_write_xmp__mutmut_5': xǁXmpPerPageMethodǁ_write_xmp__mutmut_5, 
        'xǁXmpPerPageMethodǁ_write_xmp__mutmut_6': xǁXmpPerPageMethodǁ_write_xmp__mutmut_6, 
        'xǁXmpPerPageMethodǁ_write_xmp__mutmut_7': xǁXmpPerPageMethodǁ_write_xmp__mutmut_7, 
        'xǁXmpPerPageMethodǁ_write_xmp__mutmut_8': xǁXmpPerPageMethodǁ_write_xmp__mutmut_8, 
        'xǁXmpPerPageMethodǁ_write_xmp__mutmut_9': xǁXmpPerPageMethodǁ_write_xmp__mutmut_9, 
        'xǁXmpPerPageMethodǁ_write_xmp__mutmut_10': xǁXmpPerPageMethodǁ_write_xmp__mutmut_10, 
        'xǁXmpPerPageMethodǁ_write_xmp__mutmut_11': xǁXmpPerPageMethodǁ_write_xmp__mutmut_11, 
        'xǁXmpPerPageMethodǁ_write_xmp__mutmut_12': xǁXmpPerPageMethodǁ_write_xmp__mutmut_12, 
        'xǁXmpPerPageMethodǁ_write_xmp__mutmut_13': xǁXmpPerPageMethodǁ_write_xmp__mutmut_13, 
        'xǁXmpPerPageMethodǁ_write_xmp__mutmut_14': xǁXmpPerPageMethodǁ_write_xmp__mutmut_14, 
        'xǁXmpPerPageMethodǁ_write_xmp__mutmut_15': xǁXmpPerPageMethodǁ_write_xmp__mutmut_15, 
        'xǁXmpPerPageMethodǁ_write_xmp__mutmut_16': xǁXmpPerPageMethodǁ_write_xmp__mutmut_16, 
        'xǁXmpPerPageMethodǁ_write_xmp__mutmut_17': xǁXmpPerPageMethodǁ_write_xmp__mutmut_17, 
        'xǁXmpPerPageMethodǁ_write_xmp__mutmut_18': xǁXmpPerPageMethodǁ_write_xmp__mutmut_18, 
        'xǁXmpPerPageMethodǁ_write_xmp__mutmut_19': xǁXmpPerPageMethodǁ_write_xmp__mutmut_19, 
        'xǁXmpPerPageMethodǁ_write_xmp__mutmut_20': xǁXmpPerPageMethodǁ_write_xmp__mutmut_20, 
        'xǁXmpPerPageMethodǁ_write_xmp__mutmut_21': xǁXmpPerPageMethodǁ_write_xmp__mutmut_21, 
        'xǁXmpPerPageMethodǁ_write_xmp__mutmut_22': xǁXmpPerPageMethodǁ_write_xmp__mutmut_22, 
        'xǁXmpPerPageMethodǁ_write_xmp__mutmut_23': xǁXmpPerPageMethodǁ_write_xmp__mutmut_23, 
        'xǁXmpPerPageMethodǁ_write_xmp__mutmut_24': xǁXmpPerPageMethodǁ_write_xmp__mutmut_24, 
        'xǁXmpPerPageMethodǁ_write_xmp__mutmut_25': xǁXmpPerPageMethodǁ_write_xmp__mutmut_25, 
        'xǁXmpPerPageMethodǁ_write_xmp__mutmut_26': xǁXmpPerPageMethodǁ_write_xmp__mutmut_26, 
        'xǁXmpPerPageMethodǁ_write_xmp__mutmut_27': xǁXmpPerPageMethodǁ_write_xmp__mutmut_27, 
        'xǁXmpPerPageMethodǁ_write_xmp__mutmut_28': xǁXmpPerPageMethodǁ_write_xmp__mutmut_28, 
        'xǁXmpPerPageMethodǁ_write_xmp__mutmut_29': xǁXmpPerPageMethodǁ_write_xmp__mutmut_29, 
        'xǁXmpPerPageMethodǁ_write_xmp__mutmut_30': xǁXmpPerPageMethodǁ_write_xmp__mutmut_30, 
        'xǁXmpPerPageMethodǁ_write_xmp__mutmut_31': xǁXmpPerPageMethodǁ_write_xmp__mutmut_31, 
        'xǁXmpPerPageMethodǁ_write_xmp__mutmut_32': xǁXmpPerPageMethodǁ_write_xmp__mutmut_32, 
        'xǁXmpPerPageMethodǁ_write_xmp__mutmut_33': xǁXmpPerPageMethodǁ_write_xmp__mutmut_33, 
        'xǁXmpPerPageMethodǁ_write_xmp__mutmut_34': xǁXmpPerPageMethodǁ_write_xmp__mutmut_34, 
        'xǁXmpPerPageMethodǁ_write_xmp__mutmut_35': xǁXmpPerPageMethodǁ_write_xmp__mutmut_35, 
        'xǁXmpPerPageMethodǁ_write_xmp__mutmut_36': xǁXmpPerPageMethodǁ_write_xmp__mutmut_36, 
        'xǁXmpPerPageMethodǁ_write_xmp__mutmut_37': xǁXmpPerPageMethodǁ_write_xmp__mutmut_37, 
        'xǁXmpPerPageMethodǁ_write_xmp__mutmut_38': xǁXmpPerPageMethodǁ_write_xmp__mutmut_38, 
        'xǁXmpPerPageMethodǁ_write_xmp__mutmut_39': xǁXmpPerPageMethodǁ_write_xmp__mutmut_39, 
        'xǁXmpPerPageMethodǁ_write_xmp__mutmut_40': xǁXmpPerPageMethodǁ_write_xmp__mutmut_40
    }
    
    def _write_xmp(self, *args, **kwargs):
        result = _mutmut_trampoline(object.__getattribute__(self, "xǁXmpPerPageMethodǁ_write_xmp__mutmut_orig"), object.__getattribute__(self, "xǁXmpPerPageMethodǁ_write_xmp__mutmut_mutants"), args, kwargs, self)
        return result 
    
    _write_xmp.__signature__ = _mutmut_signature(xǁXmpPerPageMethodǁ_write_xmp__mutmut_orig)
    xǁXmpPerPageMethodǁ_write_xmp__mutmut_orig.__name__ = 'xǁXmpPerPageMethodǁ_write_xmp'

    # ------------------------
    # Publika metoder (kontrakt)
    # ------------------------

    def xǁXmpPerPageMethodǁadd_watermark__mutmut_orig(
        self,
        pdf: PdfSource,
        secret: str,
        key: str,
        position: Optional[str] = None,
    ) -> bytes:
        """Skriv XMP-fält: method, secret, page_count och p{i}_{salt,mac}."""
        if not secret:
            raise ValueError("secret must be non-empty")
        if len(secret) > 128:
            raise ValueError("secret too long (max 128 chars)")

        key_b = _key_to_bytes(key)
        out_mem = io.BytesIO()

        try:
            with self._open_pdf(pdf) as doc:
                self._write_xmp(doc, secret, key_b)
                doc.save(out_mem)
        except Exception:
            doc = pikepdf.Pdf.new()
            doc.add_blank_page()
            self._write_xmp(doc, secret, key_b)
            doc.save(out_mem)

        out_mem.seek(0)
        return out_mem.read()

    # ------------------------
    # Publika metoder (kontrakt)
    # ------------------------

    def xǁXmpPerPageMethodǁadd_watermark__mutmut_1(
        self,
        pdf: PdfSource,
        secret: str,
        key: str,
        position: Optional[str] = None,
    ) -> bytes:
        """Skriv XMP-fält: method, secret, page_count och p{i}_{salt,mac}."""
        if secret:
            raise ValueError("secret must be non-empty")
        if len(secret) > 128:
            raise ValueError("secret too long (max 128 chars)")

        key_b = _key_to_bytes(key)
        out_mem = io.BytesIO()

        try:
            with self._open_pdf(pdf) as doc:
                self._write_xmp(doc, secret, key_b)
                doc.save(out_mem)
        except Exception:
            doc = pikepdf.Pdf.new()
            doc.add_blank_page()
            self._write_xmp(doc, secret, key_b)
            doc.save(out_mem)

        out_mem.seek(0)
        return out_mem.read()

    # ------------------------
    # Publika metoder (kontrakt)
    # ------------------------

    def xǁXmpPerPageMethodǁadd_watermark__mutmut_2(
        self,
        pdf: PdfSource,
        secret: str,
        key: str,
        position: Optional[str] = None,
    ) -> bytes:
        """Skriv XMP-fält: method, secret, page_count och p{i}_{salt,mac}."""
        if not secret:
            raise ValueError(None)
        if len(secret) > 128:
            raise ValueError("secret too long (max 128 chars)")

        key_b = _key_to_bytes(key)
        out_mem = io.BytesIO()

        try:
            with self._open_pdf(pdf) as doc:
                self._write_xmp(doc, secret, key_b)
                doc.save(out_mem)
        except Exception:
            doc = pikepdf.Pdf.new()
            doc.add_blank_page()
            self._write_xmp(doc, secret, key_b)
            doc.save(out_mem)

        out_mem.seek(0)
        return out_mem.read()

    # ------------------------
    # Publika metoder (kontrakt)
    # ------------------------

    def xǁXmpPerPageMethodǁadd_watermark__mutmut_3(
        self,
        pdf: PdfSource,
        secret: str,
        key: str,
        position: Optional[str] = None,
    ) -> bytes:
        """Skriv XMP-fält: method, secret, page_count och p{i}_{salt,mac}."""
        if not secret:
            raise ValueError("XXsecret must be non-emptyXX")
        if len(secret) > 128:
            raise ValueError("secret too long (max 128 chars)")

        key_b = _key_to_bytes(key)
        out_mem = io.BytesIO()

        try:
            with self._open_pdf(pdf) as doc:
                self._write_xmp(doc, secret, key_b)
                doc.save(out_mem)
        except Exception:
            doc = pikepdf.Pdf.new()
            doc.add_blank_page()
            self._write_xmp(doc, secret, key_b)
            doc.save(out_mem)

        out_mem.seek(0)
        return out_mem.read()

    # ------------------------
    # Publika metoder (kontrakt)
    # ------------------------

    def xǁXmpPerPageMethodǁadd_watermark__mutmut_4(
        self,
        pdf: PdfSource,
        secret: str,
        key: str,
        position: Optional[str] = None,
    ) -> bytes:
        """Skriv XMP-fält: method, secret, page_count och p{i}_{salt,mac}."""
        if not secret:
            raise ValueError("SECRET MUST BE NON-EMPTY")
        if len(secret) > 128:
            raise ValueError("secret too long (max 128 chars)")

        key_b = _key_to_bytes(key)
        out_mem = io.BytesIO()

        try:
            with self._open_pdf(pdf) as doc:
                self._write_xmp(doc, secret, key_b)
                doc.save(out_mem)
        except Exception:
            doc = pikepdf.Pdf.new()
            doc.add_blank_page()
            self._write_xmp(doc, secret, key_b)
            doc.save(out_mem)

        out_mem.seek(0)
        return out_mem.read()

    # ------------------------
    # Publika metoder (kontrakt)
    # ------------------------

    def xǁXmpPerPageMethodǁadd_watermark__mutmut_5(
        self,
        pdf: PdfSource,
        secret: str,
        key: str,
        position: Optional[str] = None,
    ) -> bytes:
        """Skriv XMP-fält: method, secret, page_count och p{i}_{salt,mac}."""
        if not secret:
            raise ValueError("secret must be non-empty")
        if len(secret) >= 128:
            raise ValueError("secret too long (max 128 chars)")

        key_b = _key_to_bytes(key)
        out_mem = io.BytesIO()

        try:
            with self._open_pdf(pdf) as doc:
                self._write_xmp(doc, secret, key_b)
                doc.save(out_mem)
        except Exception:
            doc = pikepdf.Pdf.new()
            doc.add_blank_page()
            self._write_xmp(doc, secret, key_b)
            doc.save(out_mem)

        out_mem.seek(0)
        return out_mem.read()

    # ------------------------
    # Publika metoder (kontrakt)
    # ------------------------

    def xǁXmpPerPageMethodǁadd_watermark__mutmut_6(
        self,
        pdf: PdfSource,
        secret: str,
        key: str,
        position: Optional[str] = None,
    ) -> bytes:
        """Skriv XMP-fält: method, secret, page_count och p{i}_{salt,mac}."""
        if not secret:
            raise ValueError("secret must be non-empty")
        if len(secret) > 129:
            raise ValueError("secret too long (max 128 chars)")

        key_b = _key_to_bytes(key)
        out_mem = io.BytesIO()

        try:
            with self._open_pdf(pdf) as doc:
                self._write_xmp(doc, secret, key_b)
                doc.save(out_mem)
        except Exception:
            doc = pikepdf.Pdf.new()
            doc.add_blank_page()
            self._write_xmp(doc, secret, key_b)
            doc.save(out_mem)

        out_mem.seek(0)
        return out_mem.read()

    # ------------------------
    # Publika metoder (kontrakt)
    # ------------------------

    def xǁXmpPerPageMethodǁadd_watermark__mutmut_7(
        self,
        pdf: PdfSource,
        secret: str,
        key: str,
        position: Optional[str] = None,
    ) -> bytes:
        """Skriv XMP-fält: method, secret, page_count och p{i}_{salt,mac}."""
        if not secret:
            raise ValueError("secret must be non-empty")
        if len(secret) > 128:
            raise ValueError(None)

        key_b = _key_to_bytes(key)
        out_mem = io.BytesIO()

        try:
            with self._open_pdf(pdf) as doc:
                self._write_xmp(doc, secret, key_b)
                doc.save(out_mem)
        except Exception:
            doc = pikepdf.Pdf.new()
            doc.add_blank_page()
            self._write_xmp(doc, secret, key_b)
            doc.save(out_mem)

        out_mem.seek(0)
        return out_mem.read()

    # ------------------------
    # Publika metoder (kontrakt)
    # ------------------------

    def xǁXmpPerPageMethodǁadd_watermark__mutmut_8(
        self,
        pdf: PdfSource,
        secret: str,
        key: str,
        position: Optional[str] = None,
    ) -> bytes:
        """Skriv XMP-fält: method, secret, page_count och p{i}_{salt,mac}."""
        if not secret:
            raise ValueError("secret must be non-empty")
        if len(secret) > 128:
            raise ValueError("XXsecret too long (max 128 chars)XX")

        key_b = _key_to_bytes(key)
        out_mem = io.BytesIO()

        try:
            with self._open_pdf(pdf) as doc:
                self._write_xmp(doc, secret, key_b)
                doc.save(out_mem)
        except Exception:
            doc = pikepdf.Pdf.new()
            doc.add_blank_page()
            self._write_xmp(doc, secret, key_b)
            doc.save(out_mem)

        out_mem.seek(0)
        return out_mem.read()

    # ------------------------
    # Publika metoder (kontrakt)
    # ------------------------

    def xǁXmpPerPageMethodǁadd_watermark__mutmut_9(
        self,
        pdf: PdfSource,
        secret: str,
        key: str,
        position: Optional[str] = None,
    ) -> bytes:
        """Skriv XMP-fält: method, secret, page_count och p{i}_{salt,mac}."""
        if not secret:
            raise ValueError("secret must be non-empty")
        if len(secret) > 128:
            raise ValueError("SECRET TOO LONG (MAX 128 CHARS)")

        key_b = _key_to_bytes(key)
        out_mem = io.BytesIO()

        try:
            with self._open_pdf(pdf) as doc:
                self._write_xmp(doc, secret, key_b)
                doc.save(out_mem)
        except Exception:
            doc = pikepdf.Pdf.new()
            doc.add_blank_page()
            self._write_xmp(doc, secret, key_b)
            doc.save(out_mem)

        out_mem.seek(0)
        return out_mem.read()

    # ------------------------
    # Publika metoder (kontrakt)
    # ------------------------

    def xǁXmpPerPageMethodǁadd_watermark__mutmut_10(
        self,
        pdf: PdfSource,
        secret: str,
        key: str,
        position: Optional[str] = None,
    ) -> bytes:
        """Skriv XMP-fält: method, secret, page_count och p{i}_{salt,mac}."""
        if not secret:
            raise ValueError("secret must be non-empty")
        if len(secret) > 128:
            raise ValueError("secret too long (max 128 chars)")

        key_b = None
        out_mem = io.BytesIO()

        try:
            with self._open_pdf(pdf) as doc:
                self._write_xmp(doc, secret, key_b)
                doc.save(out_mem)
        except Exception:
            doc = pikepdf.Pdf.new()
            doc.add_blank_page()
            self._write_xmp(doc, secret, key_b)
            doc.save(out_mem)

        out_mem.seek(0)
        return out_mem.read()

    # ------------------------
    # Publika metoder (kontrakt)
    # ------------------------

    def xǁXmpPerPageMethodǁadd_watermark__mutmut_11(
        self,
        pdf: PdfSource,
        secret: str,
        key: str,
        position: Optional[str] = None,
    ) -> bytes:
        """Skriv XMP-fält: method, secret, page_count och p{i}_{salt,mac}."""
        if not secret:
            raise ValueError("secret must be non-empty")
        if len(secret) > 128:
            raise ValueError("secret too long (max 128 chars)")

        key_b = _key_to_bytes(None)
        out_mem = io.BytesIO()

        try:
            with self._open_pdf(pdf) as doc:
                self._write_xmp(doc, secret, key_b)
                doc.save(out_mem)
        except Exception:
            doc = pikepdf.Pdf.new()
            doc.add_blank_page()
            self._write_xmp(doc, secret, key_b)
            doc.save(out_mem)

        out_mem.seek(0)
        return out_mem.read()

    # ------------------------
    # Publika metoder (kontrakt)
    # ------------------------

    def xǁXmpPerPageMethodǁadd_watermark__mutmut_12(
        self,
        pdf: PdfSource,
        secret: str,
        key: str,
        position: Optional[str] = None,
    ) -> bytes:
        """Skriv XMP-fält: method, secret, page_count och p{i}_{salt,mac}."""
        if not secret:
            raise ValueError("secret must be non-empty")
        if len(secret) > 128:
            raise ValueError("secret too long (max 128 chars)")

        key_b = _key_to_bytes(key)
        out_mem = None

        try:
            with self._open_pdf(pdf) as doc:
                self._write_xmp(doc, secret, key_b)
                doc.save(out_mem)
        except Exception:
            doc = pikepdf.Pdf.new()
            doc.add_blank_page()
            self._write_xmp(doc, secret, key_b)
            doc.save(out_mem)

        out_mem.seek(0)
        return out_mem.read()

    # ------------------------
    # Publika metoder (kontrakt)
    # ------------------------

    def xǁXmpPerPageMethodǁadd_watermark__mutmut_13(
        self,
        pdf: PdfSource,
        secret: str,
        key: str,
        position: Optional[str] = None,
    ) -> bytes:
        """Skriv XMP-fält: method, secret, page_count och p{i}_{salt,mac}."""
        if not secret:
            raise ValueError("secret must be non-empty")
        if len(secret) > 128:
            raise ValueError("secret too long (max 128 chars)")

        key_b = _key_to_bytes(key)
        out_mem = io.BytesIO()

        try:
            with self._open_pdf(None) as doc:
                self._write_xmp(doc, secret, key_b)
                doc.save(out_mem)
        except Exception:
            doc = pikepdf.Pdf.new()
            doc.add_blank_page()
            self._write_xmp(doc, secret, key_b)
            doc.save(out_mem)

        out_mem.seek(0)
        return out_mem.read()

    # ------------------------
    # Publika metoder (kontrakt)
    # ------------------------

    def xǁXmpPerPageMethodǁadd_watermark__mutmut_14(
        self,
        pdf: PdfSource,
        secret: str,
        key: str,
        position: Optional[str] = None,
    ) -> bytes:
        """Skriv XMP-fält: method, secret, page_count och p{i}_{salt,mac}."""
        if not secret:
            raise ValueError("secret must be non-empty")
        if len(secret) > 128:
            raise ValueError("secret too long (max 128 chars)")

        key_b = _key_to_bytes(key)
        out_mem = io.BytesIO()

        try:
            with self._open_pdf(pdf) as doc:
                self._write_xmp(None, secret, key_b)
                doc.save(out_mem)
        except Exception:
            doc = pikepdf.Pdf.new()
            doc.add_blank_page()
            self._write_xmp(doc, secret, key_b)
            doc.save(out_mem)

        out_mem.seek(0)
        return out_mem.read()

    # ------------------------
    # Publika metoder (kontrakt)
    # ------------------------

    def xǁXmpPerPageMethodǁadd_watermark__mutmut_15(
        self,
        pdf: PdfSource,
        secret: str,
        key: str,
        position: Optional[str] = None,
    ) -> bytes:
        """Skriv XMP-fält: method, secret, page_count och p{i}_{salt,mac}."""
        if not secret:
            raise ValueError("secret must be non-empty")
        if len(secret) > 128:
            raise ValueError("secret too long (max 128 chars)")

        key_b = _key_to_bytes(key)
        out_mem = io.BytesIO()

        try:
            with self._open_pdf(pdf) as doc:
                self._write_xmp(doc, None, key_b)
                doc.save(out_mem)
        except Exception:
            doc = pikepdf.Pdf.new()
            doc.add_blank_page()
            self._write_xmp(doc, secret, key_b)
            doc.save(out_mem)

        out_mem.seek(0)
        return out_mem.read()

    # ------------------------
    # Publika metoder (kontrakt)
    # ------------------------

    def xǁXmpPerPageMethodǁadd_watermark__mutmut_16(
        self,
        pdf: PdfSource,
        secret: str,
        key: str,
        position: Optional[str] = None,
    ) -> bytes:
        """Skriv XMP-fält: method, secret, page_count och p{i}_{salt,mac}."""
        if not secret:
            raise ValueError("secret must be non-empty")
        if len(secret) > 128:
            raise ValueError("secret too long (max 128 chars)")

        key_b = _key_to_bytes(key)
        out_mem = io.BytesIO()

        try:
            with self._open_pdf(pdf) as doc:
                self._write_xmp(doc, secret, None)
                doc.save(out_mem)
        except Exception:
            doc = pikepdf.Pdf.new()
            doc.add_blank_page()
            self._write_xmp(doc, secret, key_b)
            doc.save(out_mem)

        out_mem.seek(0)
        return out_mem.read()

    # ------------------------
    # Publika metoder (kontrakt)
    # ------------------------

    def xǁXmpPerPageMethodǁadd_watermark__mutmut_17(
        self,
        pdf: PdfSource,
        secret: str,
        key: str,
        position: Optional[str] = None,
    ) -> bytes:
        """Skriv XMP-fält: method, secret, page_count och p{i}_{salt,mac}."""
        if not secret:
            raise ValueError("secret must be non-empty")
        if len(secret) > 128:
            raise ValueError("secret too long (max 128 chars)")

        key_b = _key_to_bytes(key)
        out_mem = io.BytesIO()

        try:
            with self._open_pdf(pdf) as doc:
                self._write_xmp(secret, key_b)
                doc.save(out_mem)
        except Exception:
            doc = pikepdf.Pdf.new()
            doc.add_blank_page()
            self._write_xmp(doc, secret, key_b)
            doc.save(out_mem)

        out_mem.seek(0)
        return out_mem.read()

    # ------------------------
    # Publika metoder (kontrakt)
    # ------------------------

    def xǁXmpPerPageMethodǁadd_watermark__mutmut_18(
        self,
        pdf: PdfSource,
        secret: str,
        key: str,
        position: Optional[str] = None,
    ) -> bytes:
        """Skriv XMP-fält: method, secret, page_count och p{i}_{salt,mac}."""
        if not secret:
            raise ValueError("secret must be non-empty")
        if len(secret) > 128:
            raise ValueError("secret too long (max 128 chars)")

        key_b = _key_to_bytes(key)
        out_mem = io.BytesIO()

        try:
            with self._open_pdf(pdf) as doc:
                self._write_xmp(doc, key_b)
                doc.save(out_mem)
        except Exception:
            doc = pikepdf.Pdf.new()
            doc.add_blank_page()
            self._write_xmp(doc, secret, key_b)
            doc.save(out_mem)

        out_mem.seek(0)
        return out_mem.read()

    # ------------------------
    # Publika metoder (kontrakt)
    # ------------------------

    def xǁXmpPerPageMethodǁadd_watermark__mutmut_19(
        self,
        pdf: PdfSource,
        secret: str,
        key: str,
        position: Optional[str] = None,
    ) -> bytes:
        """Skriv XMP-fält: method, secret, page_count och p{i}_{salt,mac}."""
        if not secret:
            raise ValueError("secret must be non-empty")
        if len(secret) > 128:
            raise ValueError("secret too long (max 128 chars)")

        key_b = _key_to_bytes(key)
        out_mem = io.BytesIO()

        try:
            with self._open_pdf(pdf) as doc:
                self._write_xmp(doc, secret, )
                doc.save(out_mem)
        except Exception:
            doc = pikepdf.Pdf.new()
            doc.add_blank_page()
            self._write_xmp(doc, secret, key_b)
            doc.save(out_mem)

        out_mem.seek(0)
        return out_mem.read()

    # ------------------------
    # Publika metoder (kontrakt)
    # ------------------------

    def xǁXmpPerPageMethodǁadd_watermark__mutmut_20(
        self,
        pdf: PdfSource,
        secret: str,
        key: str,
        position: Optional[str] = None,
    ) -> bytes:
        """Skriv XMP-fält: method, secret, page_count och p{i}_{salt,mac}."""
        if not secret:
            raise ValueError("secret must be non-empty")
        if len(secret) > 128:
            raise ValueError("secret too long (max 128 chars)")

        key_b = _key_to_bytes(key)
        out_mem = io.BytesIO()

        try:
            with self._open_pdf(pdf) as doc:
                self._write_xmp(doc, secret, key_b)
                doc.save(None)
        except Exception:
            doc = pikepdf.Pdf.new()
            doc.add_blank_page()
            self._write_xmp(doc, secret, key_b)
            doc.save(out_mem)

        out_mem.seek(0)
        return out_mem.read()

    # ------------------------
    # Publika metoder (kontrakt)
    # ------------------------

    def xǁXmpPerPageMethodǁadd_watermark__mutmut_21(
        self,
        pdf: PdfSource,
        secret: str,
        key: str,
        position: Optional[str] = None,
    ) -> bytes:
        """Skriv XMP-fält: method, secret, page_count och p{i}_{salt,mac}."""
        if not secret:
            raise ValueError("secret must be non-empty")
        if len(secret) > 128:
            raise ValueError("secret too long (max 128 chars)")

        key_b = _key_to_bytes(key)
        out_mem = io.BytesIO()

        try:
            with self._open_pdf(pdf) as doc:
                self._write_xmp(doc, secret, key_b)
                doc.save(out_mem)
        except Exception:
            doc = None
            doc.add_blank_page()
            self._write_xmp(doc, secret, key_b)
            doc.save(out_mem)

        out_mem.seek(0)
        return out_mem.read()

    # ------------------------
    # Publika metoder (kontrakt)
    # ------------------------

    def xǁXmpPerPageMethodǁadd_watermark__mutmut_22(
        self,
        pdf: PdfSource,
        secret: str,
        key: str,
        position: Optional[str] = None,
    ) -> bytes:
        """Skriv XMP-fält: method, secret, page_count och p{i}_{salt,mac}."""
        if not secret:
            raise ValueError("secret must be non-empty")
        if len(secret) > 128:
            raise ValueError("secret too long (max 128 chars)")

        key_b = _key_to_bytes(key)
        out_mem = io.BytesIO()

        try:
            with self._open_pdf(pdf) as doc:
                self._write_xmp(doc, secret, key_b)
                doc.save(out_mem)
        except Exception:
            doc = pikepdf.Pdf.new()
            doc.add_blank_page()
            self._write_xmp(None, secret, key_b)
            doc.save(out_mem)

        out_mem.seek(0)
        return out_mem.read()

    # ------------------------
    # Publika metoder (kontrakt)
    # ------------------------

    def xǁXmpPerPageMethodǁadd_watermark__mutmut_23(
        self,
        pdf: PdfSource,
        secret: str,
        key: str,
        position: Optional[str] = None,
    ) -> bytes:
        """Skriv XMP-fält: method, secret, page_count och p{i}_{salt,mac}."""
        if not secret:
            raise ValueError("secret must be non-empty")
        if len(secret) > 128:
            raise ValueError("secret too long (max 128 chars)")

        key_b = _key_to_bytes(key)
        out_mem = io.BytesIO()

        try:
            with self._open_pdf(pdf) as doc:
                self._write_xmp(doc, secret, key_b)
                doc.save(out_mem)
        except Exception:
            doc = pikepdf.Pdf.new()
            doc.add_blank_page()
            self._write_xmp(doc, None, key_b)
            doc.save(out_mem)

        out_mem.seek(0)
        return out_mem.read()

    # ------------------------
    # Publika metoder (kontrakt)
    # ------------------------

    def xǁXmpPerPageMethodǁadd_watermark__mutmut_24(
        self,
        pdf: PdfSource,
        secret: str,
        key: str,
        position: Optional[str] = None,
    ) -> bytes:
        """Skriv XMP-fält: method, secret, page_count och p{i}_{salt,mac}."""
        if not secret:
            raise ValueError("secret must be non-empty")
        if len(secret) > 128:
            raise ValueError("secret too long (max 128 chars)")

        key_b = _key_to_bytes(key)
        out_mem = io.BytesIO()

        try:
            with self._open_pdf(pdf) as doc:
                self._write_xmp(doc, secret, key_b)
                doc.save(out_mem)
        except Exception:
            doc = pikepdf.Pdf.new()
            doc.add_blank_page()
            self._write_xmp(doc, secret, None)
            doc.save(out_mem)

        out_mem.seek(0)
        return out_mem.read()

    # ------------------------
    # Publika metoder (kontrakt)
    # ------------------------

    def xǁXmpPerPageMethodǁadd_watermark__mutmut_25(
        self,
        pdf: PdfSource,
        secret: str,
        key: str,
        position: Optional[str] = None,
    ) -> bytes:
        """Skriv XMP-fält: method, secret, page_count och p{i}_{salt,mac}."""
        if not secret:
            raise ValueError("secret must be non-empty")
        if len(secret) > 128:
            raise ValueError("secret too long (max 128 chars)")

        key_b = _key_to_bytes(key)
        out_mem = io.BytesIO()

        try:
            with self._open_pdf(pdf) as doc:
                self._write_xmp(doc, secret, key_b)
                doc.save(out_mem)
        except Exception:
            doc = pikepdf.Pdf.new()
            doc.add_blank_page()
            self._write_xmp(secret, key_b)
            doc.save(out_mem)

        out_mem.seek(0)
        return out_mem.read()

    # ------------------------
    # Publika metoder (kontrakt)
    # ------------------------

    def xǁXmpPerPageMethodǁadd_watermark__mutmut_26(
        self,
        pdf: PdfSource,
        secret: str,
        key: str,
        position: Optional[str] = None,
    ) -> bytes:
        """Skriv XMP-fält: method, secret, page_count och p{i}_{salt,mac}."""
        if not secret:
            raise ValueError("secret must be non-empty")
        if len(secret) > 128:
            raise ValueError("secret too long (max 128 chars)")

        key_b = _key_to_bytes(key)
        out_mem = io.BytesIO()

        try:
            with self._open_pdf(pdf) as doc:
                self._write_xmp(doc, secret, key_b)
                doc.save(out_mem)
        except Exception:
            doc = pikepdf.Pdf.new()
            doc.add_blank_page()
            self._write_xmp(doc, key_b)
            doc.save(out_mem)

        out_mem.seek(0)
        return out_mem.read()

    # ------------------------
    # Publika metoder (kontrakt)
    # ------------------------

    def xǁXmpPerPageMethodǁadd_watermark__mutmut_27(
        self,
        pdf: PdfSource,
        secret: str,
        key: str,
        position: Optional[str] = None,
    ) -> bytes:
        """Skriv XMP-fält: method, secret, page_count och p{i}_{salt,mac}."""
        if not secret:
            raise ValueError("secret must be non-empty")
        if len(secret) > 128:
            raise ValueError("secret too long (max 128 chars)")

        key_b = _key_to_bytes(key)
        out_mem = io.BytesIO()

        try:
            with self._open_pdf(pdf) as doc:
                self._write_xmp(doc, secret, key_b)
                doc.save(out_mem)
        except Exception:
            doc = pikepdf.Pdf.new()
            doc.add_blank_page()
            self._write_xmp(doc, secret, )
            doc.save(out_mem)

        out_mem.seek(0)
        return out_mem.read()

    # ------------------------
    # Publika metoder (kontrakt)
    # ------------------------

    def xǁXmpPerPageMethodǁadd_watermark__mutmut_28(
        self,
        pdf: PdfSource,
        secret: str,
        key: str,
        position: Optional[str] = None,
    ) -> bytes:
        """Skriv XMP-fält: method, secret, page_count och p{i}_{salt,mac}."""
        if not secret:
            raise ValueError("secret must be non-empty")
        if len(secret) > 128:
            raise ValueError("secret too long (max 128 chars)")

        key_b = _key_to_bytes(key)
        out_mem = io.BytesIO()

        try:
            with self._open_pdf(pdf) as doc:
                self._write_xmp(doc, secret, key_b)
                doc.save(out_mem)
        except Exception:
            doc = pikepdf.Pdf.new()
            doc.add_blank_page()
            self._write_xmp(doc, secret, key_b)
            doc.save(None)

        out_mem.seek(0)
        return out_mem.read()

    # ------------------------
    # Publika metoder (kontrakt)
    # ------------------------

    def xǁXmpPerPageMethodǁadd_watermark__mutmut_29(
        self,
        pdf: PdfSource,
        secret: str,
        key: str,
        position: Optional[str] = None,
    ) -> bytes:
        """Skriv XMP-fält: method, secret, page_count och p{i}_{salt,mac}."""
        if not secret:
            raise ValueError("secret must be non-empty")
        if len(secret) > 128:
            raise ValueError("secret too long (max 128 chars)")

        key_b = _key_to_bytes(key)
        out_mem = io.BytesIO()

        try:
            with self._open_pdf(pdf) as doc:
                self._write_xmp(doc, secret, key_b)
                doc.save(out_mem)
        except Exception:
            doc = pikepdf.Pdf.new()
            doc.add_blank_page()
            self._write_xmp(doc, secret, key_b)
            doc.save(out_mem)

        out_mem.seek(None)
        return out_mem.read()

    # ------------------------
    # Publika metoder (kontrakt)
    # ------------------------

    def xǁXmpPerPageMethodǁadd_watermark__mutmut_30(
        self,
        pdf: PdfSource,
        secret: str,
        key: str,
        position: Optional[str] = None,
    ) -> bytes:
        """Skriv XMP-fält: method, secret, page_count och p{i}_{salt,mac}."""
        if not secret:
            raise ValueError("secret must be non-empty")
        if len(secret) > 128:
            raise ValueError("secret too long (max 128 chars)")

        key_b = _key_to_bytes(key)
        out_mem = io.BytesIO()

        try:
            with self._open_pdf(pdf) as doc:
                self._write_xmp(doc, secret, key_b)
                doc.save(out_mem)
        except Exception:
            doc = pikepdf.Pdf.new()
            doc.add_blank_page()
            self._write_xmp(doc, secret, key_b)
            doc.save(out_mem)

        out_mem.seek(1)
        return out_mem.read()
    
    xǁXmpPerPageMethodǁadd_watermark__mutmut_mutants : ClassVar[MutantDict] = {
    'xǁXmpPerPageMethodǁadd_watermark__mutmut_1': xǁXmpPerPageMethodǁadd_watermark__mutmut_1, 
        'xǁXmpPerPageMethodǁadd_watermark__mutmut_2': xǁXmpPerPageMethodǁadd_watermark__mutmut_2, 
        'xǁXmpPerPageMethodǁadd_watermark__mutmut_3': xǁXmpPerPageMethodǁadd_watermark__mutmut_3, 
        'xǁXmpPerPageMethodǁadd_watermark__mutmut_4': xǁXmpPerPageMethodǁadd_watermark__mutmut_4, 
        'xǁXmpPerPageMethodǁadd_watermark__mutmut_5': xǁXmpPerPageMethodǁadd_watermark__mutmut_5, 
        'xǁXmpPerPageMethodǁadd_watermark__mutmut_6': xǁXmpPerPageMethodǁadd_watermark__mutmut_6, 
        'xǁXmpPerPageMethodǁadd_watermark__mutmut_7': xǁXmpPerPageMethodǁadd_watermark__mutmut_7, 
        'xǁXmpPerPageMethodǁadd_watermark__mutmut_8': xǁXmpPerPageMethodǁadd_watermark__mutmut_8, 
        'xǁXmpPerPageMethodǁadd_watermark__mutmut_9': xǁXmpPerPageMethodǁadd_watermark__mutmut_9, 
        'xǁXmpPerPageMethodǁadd_watermark__mutmut_10': xǁXmpPerPageMethodǁadd_watermark__mutmut_10, 
        'xǁXmpPerPageMethodǁadd_watermark__mutmut_11': xǁXmpPerPageMethodǁadd_watermark__mutmut_11, 
        'xǁXmpPerPageMethodǁadd_watermark__mutmut_12': xǁXmpPerPageMethodǁadd_watermark__mutmut_12, 
        'xǁXmpPerPageMethodǁadd_watermark__mutmut_13': xǁXmpPerPageMethodǁadd_watermark__mutmut_13, 
        'xǁXmpPerPageMethodǁadd_watermark__mutmut_14': xǁXmpPerPageMethodǁadd_watermark__mutmut_14, 
        'xǁXmpPerPageMethodǁadd_watermark__mutmut_15': xǁXmpPerPageMethodǁadd_watermark__mutmut_15, 
        'xǁXmpPerPageMethodǁadd_watermark__mutmut_16': xǁXmpPerPageMethodǁadd_watermark__mutmut_16, 
        'xǁXmpPerPageMethodǁadd_watermark__mutmut_17': xǁXmpPerPageMethodǁadd_watermark__mutmut_17, 
        'xǁXmpPerPageMethodǁadd_watermark__mutmut_18': xǁXmpPerPageMethodǁadd_watermark__mutmut_18, 
        'xǁXmpPerPageMethodǁadd_watermark__mutmut_19': xǁXmpPerPageMethodǁadd_watermark__mutmut_19, 
        'xǁXmpPerPageMethodǁadd_watermark__mutmut_20': xǁXmpPerPageMethodǁadd_watermark__mutmut_20, 
        'xǁXmpPerPageMethodǁadd_watermark__mutmut_21': xǁXmpPerPageMethodǁadd_watermark__mutmut_21, 
        'xǁXmpPerPageMethodǁadd_watermark__mutmut_22': xǁXmpPerPageMethodǁadd_watermark__mutmut_22, 
        'xǁXmpPerPageMethodǁadd_watermark__mutmut_23': xǁXmpPerPageMethodǁadd_watermark__mutmut_23, 
        'xǁXmpPerPageMethodǁadd_watermark__mutmut_24': xǁXmpPerPageMethodǁadd_watermark__mutmut_24, 
        'xǁXmpPerPageMethodǁadd_watermark__mutmut_25': xǁXmpPerPageMethodǁadd_watermark__mutmut_25, 
        'xǁXmpPerPageMethodǁadd_watermark__mutmut_26': xǁXmpPerPageMethodǁadd_watermark__mutmut_26, 
        'xǁXmpPerPageMethodǁadd_watermark__mutmut_27': xǁXmpPerPageMethodǁadd_watermark__mutmut_27, 
        'xǁXmpPerPageMethodǁadd_watermark__mutmut_28': xǁXmpPerPageMethodǁadd_watermark__mutmut_28, 
        'xǁXmpPerPageMethodǁadd_watermark__mutmut_29': xǁXmpPerPageMethodǁadd_watermark__mutmut_29, 
        'xǁXmpPerPageMethodǁadd_watermark__mutmut_30': xǁXmpPerPageMethodǁadd_watermark__mutmut_30
    }
    
    def add_watermark(self, *args, **kwargs):
        result = _mutmut_trampoline(object.__getattribute__(self, "xǁXmpPerPageMethodǁadd_watermark__mutmut_orig"), object.__getattribute__(self, "xǁXmpPerPageMethodǁadd_watermark__mutmut_mutants"), args, kwargs, self)
        return result 
    
    add_watermark.__signature__ = _mutmut_signature(xǁXmpPerPageMethodǁadd_watermark__mutmut_orig)
    xǁXmpPerPageMethodǁadd_watermark__mutmut_orig.__name__ = 'xǁXmpPerPageMethodǁadd_watermark'

    def xǁXmpPerPageMethodǁread_secret__mutmut_orig(self, pdf: PdfSource, key: str) -> str:
        """Läs tillbaka 'secret' och verifiera per-sida HMAC."""
        key_b = _key_to_bytes(key)

        try:
            with self._open_pdf(pdf) as doc:
                with doc.open_metadata() as xmp:
                    secret = _xmp_get_any(xmp, "secret")
                    page_count_str = _xmp_get_any(xmp, "page_count")
        except Exception as e:
            raise SecretNotFoundError(f"Cannot open PDF to read XMP: {e}")

        if not secret:
            raise SecretNotFoundError("No wm:secret in XMP")
        try:
            page_count = int(str(page_count_str))
        except Exception:
            raise SecretNotFoundError("No/invalid wm:page_count in XMP")

        if page_count == 0:
            return str(secret)

        pages_ok = 0
        with self._open_pdf(pdf) as doc:
            with doc.open_metadata() as xmp:
                for i in range(page_count):
                    salt = _xmp_get_any(xmp, f"p{i}_salt")
                    mac = _xmp_get_any(xmp, f"p{i}_mac")
                    if salt and mac:
                        expected = _hmac_hex(key_b, (str(salt) + str(secret)).encode("utf-8"))
                        if hmac.compare_digest(str(mac), expected):
                            pages_ok += 1

        if pages_ok == 0:
            raise InvalidKeyError("HMAC verification failed on all pages")

        return str(secret)

    def xǁXmpPerPageMethodǁread_secret__mutmut_1(self, pdf: PdfSource, key: str) -> str:
        """Läs tillbaka 'secret' och verifiera per-sida HMAC."""
        key_b = None

        try:
            with self._open_pdf(pdf) as doc:
                with doc.open_metadata() as xmp:
                    secret = _xmp_get_any(xmp, "secret")
                    page_count_str = _xmp_get_any(xmp, "page_count")
        except Exception as e:
            raise SecretNotFoundError(f"Cannot open PDF to read XMP: {e}")

        if not secret:
            raise SecretNotFoundError("No wm:secret in XMP")
        try:
            page_count = int(str(page_count_str))
        except Exception:
            raise SecretNotFoundError("No/invalid wm:page_count in XMP")

        if page_count == 0:
            return str(secret)

        pages_ok = 0
        with self._open_pdf(pdf) as doc:
            with doc.open_metadata() as xmp:
                for i in range(page_count):
                    salt = _xmp_get_any(xmp, f"p{i}_salt")
                    mac = _xmp_get_any(xmp, f"p{i}_mac")
                    if salt and mac:
                        expected = _hmac_hex(key_b, (str(salt) + str(secret)).encode("utf-8"))
                        if hmac.compare_digest(str(mac), expected):
                            pages_ok += 1

        if pages_ok == 0:
            raise InvalidKeyError("HMAC verification failed on all pages")

        return str(secret)

    def xǁXmpPerPageMethodǁread_secret__mutmut_2(self, pdf: PdfSource, key: str) -> str:
        """Läs tillbaka 'secret' och verifiera per-sida HMAC."""
        key_b = _key_to_bytes(None)

        try:
            with self._open_pdf(pdf) as doc:
                with doc.open_metadata() as xmp:
                    secret = _xmp_get_any(xmp, "secret")
                    page_count_str = _xmp_get_any(xmp, "page_count")
        except Exception as e:
            raise SecretNotFoundError(f"Cannot open PDF to read XMP: {e}")

        if not secret:
            raise SecretNotFoundError("No wm:secret in XMP")
        try:
            page_count = int(str(page_count_str))
        except Exception:
            raise SecretNotFoundError("No/invalid wm:page_count in XMP")

        if page_count == 0:
            return str(secret)

        pages_ok = 0
        with self._open_pdf(pdf) as doc:
            with doc.open_metadata() as xmp:
                for i in range(page_count):
                    salt = _xmp_get_any(xmp, f"p{i}_salt")
                    mac = _xmp_get_any(xmp, f"p{i}_mac")
                    if salt and mac:
                        expected = _hmac_hex(key_b, (str(salt) + str(secret)).encode("utf-8"))
                        if hmac.compare_digest(str(mac), expected):
                            pages_ok += 1

        if pages_ok == 0:
            raise InvalidKeyError("HMAC verification failed on all pages")

        return str(secret)

    def xǁXmpPerPageMethodǁread_secret__mutmut_3(self, pdf: PdfSource, key: str) -> str:
        """Läs tillbaka 'secret' och verifiera per-sida HMAC."""
        key_b = _key_to_bytes(key)

        try:
            with self._open_pdf(None) as doc:
                with doc.open_metadata() as xmp:
                    secret = _xmp_get_any(xmp, "secret")
                    page_count_str = _xmp_get_any(xmp, "page_count")
        except Exception as e:
            raise SecretNotFoundError(f"Cannot open PDF to read XMP: {e}")

        if not secret:
            raise SecretNotFoundError("No wm:secret in XMP")
        try:
            page_count = int(str(page_count_str))
        except Exception:
            raise SecretNotFoundError("No/invalid wm:page_count in XMP")

        if page_count == 0:
            return str(secret)

        pages_ok = 0
        with self._open_pdf(pdf) as doc:
            with doc.open_metadata() as xmp:
                for i in range(page_count):
                    salt = _xmp_get_any(xmp, f"p{i}_salt")
                    mac = _xmp_get_any(xmp, f"p{i}_mac")
                    if salt and mac:
                        expected = _hmac_hex(key_b, (str(salt) + str(secret)).encode("utf-8"))
                        if hmac.compare_digest(str(mac), expected):
                            pages_ok += 1

        if pages_ok == 0:
            raise InvalidKeyError("HMAC verification failed on all pages")

        return str(secret)

    def xǁXmpPerPageMethodǁread_secret__mutmut_4(self, pdf: PdfSource, key: str) -> str:
        """Läs tillbaka 'secret' och verifiera per-sida HMAC."""
        key_b = _key_to_bytes(key)

        try:
            with self._open_pdf(pdf) as doc:
                with doc.open_metadata() as xmp:
                    secret = None
                    page_count_str = _xmp_get_any(xmp, "page_count")
        except Exception as e:
            raise SecretNotFoundError(f"Cannot open PDF to read XMP: {e}")

        if not secret:
            raise SecretNotFoundError("No wm:secret in XMP")
        try:
            page_count = int(str(page_count_str))
        except Exception:
            raise SecretNotFoundError("No/invalid wm:page_count in XMP")

        if page_count == 0:
            return str(secret)

        pages_ok = 0
        with self._open_pdf(pdf) as doc:
            with doc.open_metadata() as xmp:
                for i in range(page_count):
                    salt = _xmp_get_any(xmp, f"p{i}_salt")
                    mac = _xmp_get_any(xmp, f"p{i}_mac")
                    if salt and mac:
                        expected = _hmac_hex(key_b, (str(salt) + str(secret)).encode("utf-8"))
                        if hmac.compare_digest(str(mac), expected):
                            pages_ok += 1

        if pages_ok == 0:
            raise InvalidKeyError("HMAC verification failed on all pages")

        return str(secret)

    def xǁXmpPerPageMethodǁread_secret__mutmut_5(self, pdf: PdfSource, key: str) -> str:
        """Läs tillbaka 'secret' och verifiera per-sida HMAC."""
        key_b = _key_to_bytes(key)

        try:
            with self._open_pdf(pdf) as doc:
                with doc.open_metadata() as xmp:
                    secret = _xmp_get_any(None, "secret")
                    page_count_str = _xmp_get_any(xmp, "page_count")
        except Exception as e:
            raise SecretNotFoundError(f"Cannot open PDF to read XMP: {e}")

        if not secret:
            raise SecretNotFoundError("No wm:secret in XMP")
        try:
            page_count = int(str(page_count_str))
        except Exception:
            raise SecretNotFoundError("No/invalid wm:page_count in XMP")

        if page_count == 0:
            return str(secret)

        pages_ok = 0
        with self._open_pdf(pdf) as doc:
            with doc.open_metadata() as xmp:
                for i in range(page_count):
                    salt = _xmp_get_any(xmp, f"p{i}_salt")
                    mac = _xmp_get_any(xmp, f"p{i}_mac")
                    if salt and mac:
                        expected = _hmac_hex(key_b, (str(salt) + str(secret)).encode("utf-8"))
                        if hmac.compare_digest(str(mac), expected):
                            pages_ok += 1

        if pages_ok == 0:
            raise InvalidKeyError("HMAC verification failed on all pages")

        return str(secret)

    def xǁXmpPerPageMethodǁread_secret__mutmut_6(self, pdf: PdfSource, key: str) -> str:
        """Läs tillbaka 'secret' och verifiera per-sida HMAC."""
        key_b = _key_to_bytes(key)

        try:
            with self._open_pdf(pdf) as doc:
                with doc.open_metadata() as xmp:
                    secret = _xmp_get_any(xmp, None)
                    page_count_str = _xmp_get_any(xmp, "page_count")
        except Exception as e:
            raise SecretNotFoundError(f"Cannot open PDF to read XMP: {e}")

        if not secret:
            raise SecretNotFoundError("No wm:secret in XMP")
        try:
            page_count = int(str(page_count_str))
        except Exception:
            raise SecretNotFoundError("No/invalid wm:page_count in XMP")

        if page_count == 0:
            return str(secret)

        pages_ok = 0
        with self._open_pdf(pdf) as doc:
            with doc.open_metadata() as xmp:
                for i in range(page_count):
                    salt = _xmp_get_any(xmp, f"p{i}_salt")
                    mac = _xmp_get_any(xmp, f"p{i}_mac")
                    if salt and mac:
                        expected = _hmac_hex(key_b, (str(salt) + str(secret)).encode("utf-8"))
                        if hmac.compare_digest(str(mac), expected):
                            pages_ok += 1

        if pages_ok == 0:
            raise InvalidKeyError("HMAC verification failed on all pages")

        return str(secret)

    def xǁXmpPerPageMethodǁread_secret__mutmut_7(self, pdf: PdfSource, key: str) -> str:
        """Läs tillbaka 'secret' och verifiera per-sida HMAC."""
        key_b = _key_to_bytes(key)

        try:
            with self._open_pdf(pdf) as doc:
                with doc.open_metadata() as xmp:
                    secret = _xmp_get_any("secret")
                    page_count_str = _xmp_get_any(xmp, "page_count")
        except Exception as e:
            raise SecretNotFoundError(f"Cannot open PDF to read XMP: {e}")

        if not secret:
            raise SecretNotFoundError("No wm:secret in XMP")
        try:
            page_count = int(str(page_count_str))
        except Exception:
            raise SecretNotFoundError("No/invalid wm:page_count in XMP")

        if page_count == 0:
            return str(secret)

        pages_ok = 0
        with self._open_pdf(pdf) as doc:
            with doc.open_metadata() as xmp:
                for i in range(page_count):
                    salt = _xmp_get_any(xmp, f"p{i}_salt")
                    mac = _xmp_get_any(xmp, f"p{i}_mac")
                    if salt and mac:
                        expected = _hmac_hex(key_b, (str(salt) + str(secret)).encode("utf-8"))
                        if hmac.compare_digest(str(mac), expected):
                            pages_ok += 1

        if pages_ok == 0:
            raise InvalidKeyError("HMAC verification failed on all pages")

        return str(secret)

    def xǁXmpPerPageMethodǁread_secret__mutmut_8(self, pdf: PdfSource, key: str) -> str:
        """Läs tillbaka 'secret' och verifiera per-sida HMAC."""
        key_b = _key_to_bytes(key)

        try:
            with self._open_pdf(pdf) as doc:
                with doc.open_metadata() as xmp:
                    secret = _xmp_get_any(xmp, )
                    page_count_str = _xmp_get_any(xmp, "page_count")
        except Exception as e:
            raise SecretNotFoundError(f"Cannot open PDF to read XMP: {e}")

        if not secret:
            raise SecretNotFoundError("No wm:secret in XMP")
        try:
            page_count = int(str(page_count_str))
        except Exception:
            raise SecretNotFoundError("No/invalid wm:page_count in XMP")

        if page_count == 0:
            return str(secret)

        pages_ok = 0
        with self._open_pdf(pdf) as doc:
            with doc.open_metadata() as xmp:
                for i in range(page_count):
                    salt = _xmp_get_any(xmp, f"p{i}_salt")
                    mac = _xmp_get_any(xmp, f"p{i}_mac")
                    if salt and mac:
                        expected = _hmac_hex(key_b, (str(salt) + str(secret)).encode("utf-8"))
                        if hmac.compare_digest(str(mac), expected):
                            pages_ok += 1

        if pages_ok == 0:
            raise InvalidKeyError("HMAC verification failed on all pages")

        return str(secret)

    def xǁXmpPerPageMethodǁread_secret__mutmut_9(self, pdf: PdfSource, key: str) -> str:
        """Läs tillbaka 'secret' och verifiera per-sida HMAC."""
        key_b = _key_to_bytes(key)

        try:
            with self._open_pdf(pdf) as doc:
                with doc.open_metadata() as xmp:
                    secret = _xmp_get_any(xmp, "XXsecretXX")
                    page_count_str = _xmp_get_any(xmp, "page_count")
        except Exception as e:
            raise SecretNotFoundError(f"Cannot open PDF to read XMP: {e}")

        if not secret:
            raise SecretNotFoundError("No wm:secret in XMP")
        try:
            page_count = int(str(page_count_str))
        except Exception:
            raise SecretNotFoundError("No/invalid wm:page_count in XMP")

        if page_count == 0:
            return str(secret)

        pages_ok = 0
        with self._open_pdf(pdf) as doc:
            with doc.open_metadata() as xmp:
                for i in range(page_count):
                    salt = _xmp_get_any(xmp, f"p{i}_salt")
                    mac = _xmp_get_any(xmp, f"p{i}_mac")
                    if salt and mac:
                        expected = _hmac_hex(key_b, (str(salt) + str(secret)).encode("utf-8"))
                        if hmac.compare_digest(str(mac), expected):
                            pages_ok += 1

        if pages_ok == 0:
            raise InvalidKeyError("HMAC verification failed on all pages")

        return str(secret)

    def xǁXmpPerPageMethodǁread_secret__mutmut_10(self, pdf: PdfSource, key: str) -> str:
        """Läs tillbaka 'secret' och verifiera per-sida HMAC."""
        key_b = _key_to_bytes(key)

        try:
            with self._open_pdf(pdf) as doc:
                with doc.open_metadata() as xmp:
                    secret = _xmp_get_any(xmp, "SECRET")
                    page_count_str = _xmp_get_any(xmp, "page_count")
        except Exception as e:
            raise SecretNotFoundError(f"Cannot open PDF to read XMP: {e}")

        if not secret:
            raise SecretNotFoundError("No wm:secret in XMP")
        try:
            page_count = int(str(page_count_str))
        except Exception:
            raise SecretNotFoundError("No/invalid wm:page_count in XMP")

        if page_count == 0:
            return str(secret)

        pages_ok = 0
        with self._open_pdf(pdf) as doc:
            with doc.open_metadata() as xmp:
                for i in range(page_count):
                    salt = _xmp_get_any(xmp, f"p{i}_salt")
                    mac = _xmp_get_any(xmp, f"p{i}_mac")
                    if salt and mac:
                        expected = _hmac_hex(key_b, (str(salt) + str(secret)).encode("utf-8"))
                        if hmac.compare_digest(str(mac), expected):
                            pages_ok += 1

        if pages_ok == 0:
            raise InvalidKeyError("HMAC verification failed on all pages")

        return str(secret)

    def xǁXmpPerPageMethodǁread_secret__mutmut_11(self, pdf: PdfSource, key: str) -> str:
        """Läs tillbaka 'secret' och verifiera per-sida HMAC."""
        key_b = _key_to_bytes(key)

        try:
            with self._open_pdf(pdf) as doc:
                with doc.open_metadata() as xmp:
                    secret = _xmp_get_any(xmp, "secret")
                    page_count_str = None
        except Exception as e:
            raise SecretNotFoundError(f"Cannot open PDF to read XMP: {e}")

        if not secret:
            raise SecretNotFoundError("No wm:secret in XMP")
        try:
            page_count = int(str(page_count_str))
        except Exception:
            raise SecretNotFoundError("No/invalid wm:page_count in XMP")

        if page_count == 0:
            return str(secret)

        pages_ok = 0
        with self._open_pdf(pdf) as doc:
            with doc.open_metadata() as xmp:
                for i in range(page_count):
                    salt = _xmp_get_any(xmp, f"p{i}_salt")
                    mac = _xmp_get_any(xmp, f"p{i}_mac")
                    if salt and mac:
                        expected = _hmac_hex(key_b, (str(salt) + str(secret)).encode("utf-8"))
                        if hmac.compare_digest(str(mac), expected):
                            pages_ok += 1

        if pages_ok == 0:
            raise InvalidKeyError("HMAC verification failed on all pages")

        return str(secret)

    def xǁXmpPerPageMethodǁread_secret__mutmut_12(self, pdf: PdfSource, key: str) -> str:
        """Läs tillbaka 'secret' och verifiera per-sida HMAC."""
        key_b = _key_to_bytes(key)

        try:
            with self._open_pdf(pdf) as doc:
                with doc.open_metadata() as xmp:
                    secret = _xmp_get_any(xmp, "secret")
                    page_count_str = _xmp_get_any(None, "page_count")
        except Exception as e:
            raise SecretNotFoundError(f"Cannot open PDF to read XMP: {e}")

        if not secret:
            raise SecretNotFoundError("No wm:secret in XMP")
        try:
            page_count = int(str(page_count_str))
        except Exception:
            raise SecretNotFoundError("No/invalid wm:page_count in XMP")

        if page_count == 0:
            return str(secret)

        pages_ok = 0
        with self._open_pdf(pdf) as doc:
            with doc.open_metadata() as xmp:
                for i in range(page_count):
                    salt = _xmp_get_any(xmp, f"p{i}_salt")
                    mac = _xmp_get_any(xmp, f"p{i}_mac")
                    if salt and mac:
                        expected = _hmac_hex(key_b, (str(salt) + str(secret)).encode("utf-8"))
                        if hmac.compare_digest(str(mac), expected):
                            pages_ok += 1

        if pages_ok == 0:
            raise InvalidKeyError("HMAC verification failed on all pages")

        return str(secret)

    def xǁXmpPerPageMethodǁread_secret__mutmut_13(self, pdf: PdfSource, key: str) -> str:
        """Läs tillbaka 'secret' och verifiera per-sida HMAC."""
        key_b = _key_to_bytes(key)

        try:
            with self._open_pdf(pdf) as doc:
                with doc.open_metadata() as xmp:
                    secret = _xmp_get_any(xmp, "secret")
                    page_count_str = _xmp_get_any(xmp, None)
        except Exception as e:
            raise SecretNotFoundError(f"Cannot open PDF to read XMP: {e}")

        if not secret:
            raise SecretNotFoundError("No wm:secret in XMP")
        try:
            page_count = int(str(page_count_str))
        except Exception:
            raise SecretNotFoundError("No/invalid wm:page_count in XMP")

        if page_count == 0:
            return str(secret)

        pages_ok = 0
        with self._open_pdf(pdf) as doc:
            with doc.open_metadata() as xmp:
                for i in range(page_count):
                    salt = _xmp_get_any(xmp, f"p{i}_salt")
                    mac = _xmp_get_any(xmp, f"p{i}_mac")
                    if salt and mac:
                        expected = _hmac_hex(key_b, (str(salt) + str(secret)).encode("utf-8"))
                        if hmac.compare_digest(str(mac), expected):
                            pages_ok += 1

        if pages_ok == 0:
            raise InvalidKeyError("HMAC verification failed on all pages")

        return str(secret)

    def xǁXmpPerPageMethodǁread_secret__mutmut_14(self, pdf: PdfSource, key: str) -> str:
        """Läs tillbaka 'secret' och verifiera per-sida HMAC."""
        key_b = _key_to_bytes(key)

        try:
            with self._open_pdf(pdf) as doc:
                with doc.open_metadata() as xmp:
                    secret = _xmp_get_any(xmp, "secret")
                    page_count_str = _xmp_get_any("page_count")
        except Exception as e:
            raise SecretNotFoundError(f"Cannot open PDF to read XMP: {e}")

        if not secret:
            raise SecretNotFoundError("No wm:secret in XMP")
        try:
            page_count = int(str(page_count_str))
        except Exception:
            raise SecretNotFoundError("No/invalid wm:page_count in XMP")

        if page_count == 0:
            return str(secret)

        pages_ok = 0
        with self._open_pdf(pdf) as doc:
            with doc.open_metadata() as xmp:
                for i in range(page_count):
                    salt = _xmp_get_any(xmp, f"p{i}_salt")
                    mac = _xmp_get_any(xmp, f"p{i}_mac")
                    if salt and mac:
                        expected = _hmac_hex(key_b, (str(salt) + str(secret)).encode("utf-8"))
                        if hmac.compare_digest(str(mac), expected):
                            pages_ok += 1

        if pages_ok == 0:
            raise InvalidKeyError("HMAC verification failed on all pages")

        return str(secret)

    def xǁXmpPerPageMethodǁread_secret__mutmut_15(self, pdf: PdfSource, key: str) -> str:
        """Läs tillbaka 'secret' och verifiera per-sida HMAC."""
        key_b = _key_to_bytes(key)

        try:
            with self._open_pdf(pdf) as doc:
                with doc.open_metadata() as xmp:
                    secret = _xmp_get_any(xmp, "secret")
                    page_count_str = _xmp_get_any(xmp, )
        except Exception as e:
            raise SecretNotFoundError(f"Cannot open PDF to read XMP: {e}")

        if not secret:
            raise SecretNotFoundError("No wm:secret in XMP")
        try:
            page_count = int(str(page_count_str))
        except Exception:
            raise SecretNotFoundError("No/invalid wm:page_count in XMP")

        if page_count == 0:
            return str(secret)

        pages_ok = 0
        with self._open_pdf(pdf) as doc:
            with doc.open_metadata() as xmp:
                for i in range(page_count):
                    salt = _xmp_get_any(xmp, f"p{i}_salt")
                    mac = _xmp_get_any(xmp, f"p{i}_mac")
                    if salt and mac:
                        expected = _hmac_hex(key_b, (str(salt) + str(secret)).encode("utf-8"))
                        if hmac.compare_digest(str(mac), expected):
                            pages_ok += 1

        if pages_ok == 0:
            raise InvalidKeyError("HMAC verification failed on all pages")

        return str(secret)

    def xǁXmpPerPageMethodǁread_secret__mutmut_16(self, pdf: PdfSource, key: str) -> str:
        """Läs tillbaka 'secret' och verifiera per-sida HMAC."""
        key_b = _key_to_bytes(key)

        try:
            with self._open_pdf(pdf) as doc:
                with doc.open_metadata() as xmp:
                    secret = _xmp_get_any(xmp, "secret")
                    page_count_str = _xmp_get_any(xmp, "XXpage_countXX")
        except Exception as e:
            raise SecretNotFoundError(f"Cannot open PDF to read XMP: {e}")

        if not secret:
            raise SecretNotFoundError("No wm:secret in XMP")
        try:
            page_count = int(str(page_count_str))
        except Exception:
            raise SecretNotFoundError("No/invalid wm:page_count in XMP")

        if page_count == 0:
            return str(secret)

        pages_ok = 0
        with self._open_pdf(pdf) as doc:
            with doc.open_metadata() as xmp:
                for i in range(page_count):
                    salt = _xmp_get_any(xmp, f"p{i}_salt")
                    mac = _xmp_get_any(xmp, f"p{i}_mac")
                    if salt and mac:
                        expected = _hmac_hex(key_b, (str(salt) + str(secret)).encode("utf-8"))
                        if hmac.compare_digest(str(mac), expected):
                            pages_ok += 1

        if pages_ok == 0:
            raise InvalidKeyError("HMAC verification failed on all pages")

        return str(secret)

    def xǁXmpPerPageMethodǁread_secret__mutmut_17(self, pdf: PdfSource, key: str) -> str:
        """Läs tillbaka 'secret' och verifiera per-sida HMAC."""
        key_b = _key_to_bytes(key)

        try:
            with self._open_pdf(pdf) as doc:
                with doc.open_metadata() as xmp:
                    secret = _xmp_get_any(xmp, "secret")
                    page_count_str = _xmp_get_any(xmp, "PAGE_COUNT")
        except Exception as e:
            raise SecretNotFoundError(f"Cannot open PDF to read XMP: {e}")

        if not secret:
            raise SecretNotFoundError("No wm:secret in XMP")
        try:
            page_count = int(str(page_count_str))
        except Exception:
            raise SecretNotFoundError("No/invalid wm:page_count in XMP")

        if page_count == 0:
            return str(secret)

        pages_ok = 0
        with self._open_pdf(pdf) as doc:
            with doc.open_metadata() as xmp:
                for i in range(page_count):
                    salt = _xmp_get_any(xmp, f"p{i}_salt")
                    mac = _xmp_get_any(xmp, f"p{i}_mac")
                    if salt and mac:
                        expected = _hmac_hex(key_b, (str(salt) + str(secret)).encode("utf-8"))
                        if hmac.compare_digest(str(mac), expected):
                            pages_ok += 1

        if pages_ok == 0:
            raise InvalidKeyError("HMAC verification failed on all pages")

        return str(secret)

    def xǁXmpPerPageMethodǁread_secret__mutmut_18(self, pdf: PdfSource, key: str) -> str:
        """Läs tillbaka 'secret' och verifiera per-sida HMAC."""
        key_b = _key_to_bytes(key)

        try:
            with self._open_pdf(pdf) as doc:
                with doc.open_metadata() as xmp:
                    secret = _xmp_get_any(xmp, "secret")
                    page_count_str = _xmp_get_any(xmp, "page_count")
        except Exception as e:
            raise SecretNotFoundError(None)

        if not secret:
            raise SecretNotFoundError("No wm:secret in XMP")
        try:
            page_count = int(str(page_count_str))
        except Exception:
            raise SecretNotFoundError("No/invalid wm:page_count in XMP")

        if page_count == 0:
            return str(secret)

        pages_ok = 0
        with self._open_pdf(pdf) as doc:
            with doc.open_metadata() as xmp:
                for i in range(page_count):
                    salt = _xmp_get_any(xmp, f"p{i}_salt")
                    mac = _xmp_get_any(xmp, f"p{i}_mac")
                    if salt and mac:
                        expected = _hmac_hex(key_b, (str(salt) + str(secret)).encode("utf-8"))
                        if hmac.compare_digest(str(mac), expected):
                            pages_ok += 1

        if pages_ok == 0:
            raise InvalidKeyError("HMAC verification failed on all pages")

        return str(secret)

    def xǁXmpPerPageMethodǁread_secret__mutmut_19(self, pdf: PdfSource, key: str) -> str:
        """Läs tillbaka 'secret' och verifiera per-sida HMAC."""
        key_b = _key_to_bytes(key)

        try:
            with self._open_pdf(pdf) as doc:
                with doc.open_metadata() as xmp:
                    secret = _xmp_get_any(xmp, "secret")
                    page_count_str = _xmp_get_any(xmp, "page_count")
        except Exception as e:
            raise SecretNotFoundError(f"Cannot open PDF to read XMP: {e}")

        if secret:
            raise SecretNotFoundError("No wm:secret in XMP")
        try:
            page_count = int(str(page_count_str))
        except Exception:
            raise SecretNotFoundError("No/invalid wm:page_count in XMP")

        if page_count == 0:
            return str(secret)

        pages_ok = 0
        with self._open_pdf(pdf) as doc:
            with doc.open_metadata() as xmp:
                for i in range(page_count):
                    salt = _xmp_get_any(xmp, f"p{i}_salt")
                    mac = _xmp_get_any(xmp, f"p{i}_mac")
                    if salt and mac:
                        expected = _hmac_hex(key_b, (str(salt) + str(secret)).encode("utf-8"))
                        if hmac.compare_digest(str(mac), expected):
                            pages_ok += 1

        if pages_ok == 0:
            raise InvalidKeyError("HMAC verification failed on all pages")

        return str(secret)

    def xǁXmpPerPageMethodǁread_secret__mutmut_20(self, pdf: PdfSource, key: str) -> str:
        """Läs tillbaka 'secret' och verifiera per-sida HMAC."""
        key_b = _key_to_bytes(key)

        try:
            with self._open_pdf(pdf) as doc:
                with doc.open_metadata() as xmp:
                    secret = _xmp_get_any(xmp, "secret")
                    page_count_str = _xmp_get_any(xmp, "page_count")
        except Exception as e:
            raise SecretNotFoundError(f"Cannot open PDF to read XMP: {e}")

        if not secret:
            raise SecretNotFoundError(None)
        try:
            page_count = int(str(page_count_str))
        except Exception:
            raise SecretNotFoundError("No/invalid wm:page_count in XMP")

        if page_count == 0:
            return str(secret)

        pages_ok = 0
        with self._open_pdf(pdf) as doc:
            with doc.open_metadata() as xmp:
                for i in range(page_count):
                    salt = _xmp_get_any(xmp, f"p{i}_salt")
                    mac = _xmp_get_any(xmp, f"p{i}_mac")
                    if salt and mac:
                        expected = _hmac_hex(key_b, (str(salt) + str(secret)).encode("utf-8"))
                        if hmac.compare_digest(str(mac), expected):
                            pages_ok += 1

        if pages_ok == 0:
            raise InvalidKeyError("HMAC verification failed on all pages")

        return str(secret)

    def xǁXmpPerPageMethodǁread_secret__mutmut_21(self, pdf: PdfSource, key: str) -> str:
        """Läs tillbaka 'secret' och verifiera per-sida HMAC."""
        key_b = _key_to_bytes(key)

        try:
            with self._open_pdf(pdf) as doc:
                with doc.open_metadata() as xmp:
                    secret = _xmp_get_any(xmp, "secret")
                    page_count_str = _xmp_get_any(xmp, "page_count")
        except Exception as e:
            raise SecretNotFoundError(f"Cannot open PDF to read XMP: {e}")

        if not secret:
            raise SecretNotFoundError("XXNo wm:secret in XMPXX")
        try:
            page_count = int(str(page_count_str))
        except Exception:
            raise SecretNotFoundError("No/invalid wm:page_count in XMP")

        if page_count == 0:
            return str(secret)

        pages_ok = 0
        with self._open_pdf(pdf) as doc:
            with doc.open_metadata() as xmp:
                for i in range(page_count):
                    salt = _xmp_get_any(xmp, f"p{i}_salt")
                    mac = _xmp_get_any(xmp, f"p{i}_mac")
                    if salt and mac:
                        expected = _hmac_hex(key_b, (str(salt) + str(secret)).encode("utf-8"))
                        if hmac.compare_digest(str(mac), expected):
                            pages_ok += 1

        if pages_ok == 0:
            raise InvalidKeyError("HMAC verification failed on all pages")

        return str(secret)

    def xǁXmpPerPageMethodǁread_secret__mutmut_22(self, pdf: PdfSource, key: str) -> str:
        """Läs tillbaka 'secret' och verifiera per-sida HMAC."""
        key_b = _key_to_bytes(key)

        try:
            with self._open_pdf(pdf) as doc:
                with doc.open_metadata() as xmp:
                    secret = _xmp_get_any(xmp, "secret")
                    page_count_str = _xmp_get_any(xmp, "page_count")
        except Exception as e:
            raise SecretNotFoundError(f"Cannot open PDF to read XMP: {e}")

        if not secret:
            raise SecretNotFoundError("no wm:secret in xmp")
        try:
            page_count = int(str(page_count_str))
        except Exception:
            raise SecretNotFoundError("No/invalid wm:page_count in XMP")

        if page_count == 0:
            return str(secret)

        pages_ok = 0
        with self._open_pdf(pdf) as doc:
            with doc.open_metadata() as xmp:
                for i in range(page_count):
                    salt = _xmp_get_any(xmp, f"p{i}_salt")
                    mac = _xmp_get_any(xmp, f"p{i}_mac")
                    if salt and mac:
                        expected = _hmac_hex(key_b, (str(salt) + str(secret)).encode("utf-8"))
                        if hmac.compare_digest(str(mac), expected):
                            pages_ok += 1

        if pages_ok == 0:
            raise InvalidKeyError("HMAC verification failed on all pages")

        return str(secret)

    def xǁXmpPerPageMethodǁread_secret__mutmut_23(self, pdf: PdfSource, key: str) -> str:
        """Läs tillbaka 'secret' och verifiera per-sida HMAC."""
        key_b = _key_to_bytes(key)

        try:
            with self._open_pdf(pdf) as doc:
                with doc.open_metadata() as xmp:
                    secret = _xmp_get_any(xmp, "secret")
                    page_count_str = _xmp_get_any(xmp, "page_count")
        except Exception as e:
            raise SecretNotFoundError(f"Cannot open PDF to read XMP: {e}")

        if not secret:
            raise SecretNotFoundError("NO WM:SECRET IN XMP")
        try:
            page_count = int(str(page_count_str))
        except Exception:
            raise SecretNotFoundError("No/invalid wm:page_count in XMP")

        if page_count == 0:
            return str(secret)

        pages_ok = 0
        with self._open_pdf(pdf) as doc:
            with doc.open_metadata() as xmp:
                for i in range(page_count):
                    salt = _xmp_get_any(xmp, f"p{i}_salt")
                    mac = _xmp_get_any(xmp, f"p{i}_mac")
                    if salt and mac:
                        expected = _hmac_hex(key_b, (str(salt) + str(secret)).encode("utf-8"))
                        if hmac.compare_digest(str(mac), expected):
                            pages_ok += 1

        if pages_ok == 0:
            raise InvalidKeyError("HMAC verification failed on all pages")

        return str(secret)

    def xǁXmpPerPageMethodǁread_secret__mutmut_24(self, pdf: PdfSource, key: str) -> str:
        """Läs tillbaka 'secret' och verifiera per-sida HMAC."""
        key_b = _key_to_bytes(key)

        try:
            with self._open_pdf(pdf) as doc:
                with doc.open_metadata() as xmp:
                    secret = _xmp_get_any(xmp, "secret")
                    page_count_str = _xmp_get_any(xmp, "page_count")
        except Exception as e:
            raise SecretNotFoundError(f"Cannot open PDF to read XMP: {e}")

        if not secret:
            raise SecretNotFoundError("No wm:secret in XMP")
        try:
            page_count = None
        except Exception:
            raise SecretNotFoundError("No/invalid wm:page_count in XMP")

        if page_count == 0:
            return str(secret)

        pages_ok = 0
        with self._open_pdf(pdf) as doc:
            with doc.open_metadata() as xmp:
                for i in range(page_count):
                    salt = _xmp_get_any(xmp, f"p{i}_salt")
                    mac = _xmp_get_any(xmp, f"p{i}_mac")
                    if salt and mac:
                        expected = _hmac_hex(key_b, (str(salt) + str(secret)).encode("utf-8"))
                        if hmac.compare_digest(str(mac), expected):
                            pages_ok += 1

        if pages_ok == 0:
            raise InvalidKeyError("HMAC verification failed on all pages")

        return str(secret)

    def xǁXmpPerPageMethodǁread_secret__mutmut_25(self, pdf: PdfSource, key: str) -> str:
        """Läs tillbaka 'secret' och verifiera per-sida HMAC."""
        key_b = _key_to_bytes(key)

        try:
            with self._open_pdf(pdf) as doc:
                with doc.open_metadata() as xmp:
                    secret = _xmp_get_any(xmp, "secret")
                    page_count_str = _xmp_get_any(xmp, "page_count")
        except Exception as e:
            raise SecretNotFoundError(f"Cannot open PDF to read XMP: {e}")

        if not secret:
            raise SecretNotFoundError("No wm:secret in XMP")
        try:
            page_count = int(None)
        except Exception:
            raise SecretNotFoundError("No/invalid wm:page_count in XMP")

        if page_count == 0:
            return str(secret)

        pages_ok = 0
        with self._open_pdf(pdf) as doc:
            with doc.open_metadata() as xmp:
                for i in range(page_count):
                    salt = _xmp_get_any(xmp, f"p{i}_salt")
                    mac = _xmp_get_any(xmp, f"p{i}_mac")
                    if salt and mac:
                        expected = _hmac_hex(key_b, (str(salt) + str(secret)).encode("utf-8"))
                        if hmac.compare_digest(str(mac), expected):
                            pages_ok += 1

        if pages_ok == 0:
            raise InvalidKeyError("HMAC verification failed on all pages")

        return str(secret)

    def xǁXmpPerPageMethodǁread_secret__mutmut_26(self, pdf: PdfSource, key: str) -> str:
        """Läs tillbaka 'secret' och verifiera per-sida HMAC."""
        key_b = _key_to_bytes(key)

        try:
            with self._open_pdf(pdf) as doc:
                with doc.open_metadata() as xmp:
                    secret = _xmp_get_any(xmp, "secret")
                    page_count_str = _xmp_get_any(xmp, "page_count")
        except Exception as e:
            raise SecretNotFoundError(f"Cannot open PDF to read XMP: {e}")

        if not secret:
            raise SecretNotFoundError("No wm:secret in XMP")
        try:
            page_count = int(str(None))
        except Exception:
            raise SecretNotFoundError("No/invalid wm:page_count in XMP")

        if page_count == 0:
            return str(secret)

        pages_ok = 0
        with self._open_pdf(pdf) as doc:
            with doc.open_metadata() as xmp:
                for i in range(page_count):
                    salt = _xmp_get_any(xmp, f"p{i}_salt")
                    mac = _xmp_get_any(xmp, f"p{i}_mac")
                    if salt and mac:
                        expected = _hmac_hex(key_b, (str(salt) + str(secret)).encode("utf-8"))
                        if hmac.compare_digest(str(mac), expected):
                            pages_ok += 1

        if pages_ok == 0:
            raise InvalidKeyError("HMAC verification failed on all pages")

        return str(secret)

    def xǁXmpPerPageMethodǁread_secret__mutmut_27(self, pdf: PdfSource, key: str) -> str:
        """Läs tillbaka 'secret' och verifiera per-sida HMAC."""
        key_b = _key_to_bytes(key)

        try:
            with self._open_pdf(pdf) as doc:
                with doc.open_metadata() as xmp:
                    secret = _xmp_get_any(xmp, "secret")
                    page_count_str = _xmp_get_any(xmp, "page_count")
        except Exception as e:
            raise SecretNotFoundError(f"Cannot open PDF to read XMP: {e}")

        if not secret:
            raise SecretNotFoundError("No wm:secret in XMP")
        try:
            page_count = int(str(page_count_str))
        except Exception:
            raise SecretNotFoundError(None)

        if page_count == 0:
            return str(secret)

        pages_ok = 0
        with self._open_pdf(pdf) as doc:
            with doc.open_metadata() as xmp:
                for i in range(page_count):
                    salt = _xmp_get_any(xmp, f"p{i}_salt")
                    mac = _xmp_get_any(xmp, f"p{i}_mac")
                    if salt and mac:
                        expected = _hmac_hex(key_b, (str(salt) + str(secret)).encode("utf-8"))
                        if hmac.compare_digest(str(mac), expected):
                            pages_ok += 1

        if pages_ok == 0:
            raise InvalidKeyError("HMAC verification failed on all pages")

        return str(secret)

    def xǁXmpPerPageMethodǁread_secret__mutmut_28(self, pdf: PdfSource, key: str) -> str:
        """Läs tillbaka 'secret' och verifiera per-sida HMAC."""
        key_b = _key_to_bytes(key)

        try:
            with self._open_pdf(pdf) as doc:
                with doc.open_metadata() as xmp:
                    secret = _xmp_get_any(xmp, "secret")
                    page_count_str = _xmp_get_any(xmp, "page_count")
        except Exception as e:
            raise SecretNotFoundError(f"Cannot open PDF to read XMP: {e}")

        if not secret:
            raise SecretNotFoundError("No wm:secret in XMP")
        try:
            page_count = int(str(page_count_str))
        except Exception:
            raise SecretNotFoundError("XXNo/invalid wm:page_count in XMPXX")

        if page_count == 0:
            return str(secret)

        pages_ok = 0
        with self._open_pdf(pdf) as doc:
            with doc.open_metadata() as xmp:
                for i in range(page_count):
                    salt = _xmp_get_any(xmp, f"p{i}_salt")
                    mac = _xmp_get_any(xmp, f"p{i}_mac")
                    if salt and mac:
                        expected = _hmac_hex(key_b, (str(salt) + str(secret)).encode("utf-8"))
                        if hmac.compare_digest(str(mac), expected):
                            pages_ok += 1

        if pages_ok == 0:
            raise InvalidKeyError("HMAC verification failed on all pages")

        return str(secret)

    def xǁXmpPerPageMethodǁread_secret__mutmut_29(self, pdf: PdfSource, key: str) -> str:
        """Läs tillbaka 'secret' och verifiera per-sida HMAC."""
        key_b = _key_to_bytes(key)

        try:
            with self._open_pdf(pdf) as doc:
                with doc.open_metadata() as xmp:
                    secret = _xmp_get_any(xmp, "secret")
                    page_count_str = _xmp_get_any(xmp, "page_count")
        except Exception as e:
            raise SecretNotFoundError(f"Cannot open PDF to read XMP: {e}")

        if not secret:
            raise SecretNotFoundError("No wm:secret in XMP")
        try:
            page_count = int(str(page_count_str))
        except Exception:
            raise SecretNotFoundError("no/invalid wm:page_count in xmp")

        if page_count == 0:
            return str(secret)

        pages_ok = 0
        with self._open_pdf(pdf) as doc:
            with doc.open_metadata() as xmp:
                for i in range(page_count):
                    salt = _xmp_get_any(xmp, f"p{i}_salt")
                    mac = _xmp_get_any(xmp, f"p{i}_mac")
                    if salt and mac:
                        expected = _hmac_hex(key_b, (str(salt) + str(secret)).encode("utf-8"))
                        if hmac.compare_digest(str(mac), expected):
                            pages_ok += 1

        if pages_ok == 0:
            raise InvalidKeyError("HMAC verification failed on all pages")

        return str(secret)

    def xǁXmpPerPageMethodǁread_secret__mutmut_30(self, pdf: PdfSource, key: str) -> str:
        """Läs tillbaka 'secret' och verifiera per-sida HMAC."""
        key_b = _key_to_bytes(key)

        try:
            with self._open_pdf(pdf) as doc:
                with doc.open_metadata() as xmp:
                    secret = _xmp_get_any(xmp, "secret")
                    page_count_str = _xmp_get_any(xmp, "page_count")
        except Exception as e:
            raise SecretNotFoundError(f"Cannot open PDF to read XMP: {e}")

        if not secret:
            raise SecretNotFoundError("No wm:secret in XMP")
        try:
            page_count = int(str(page_count_str))
        except Exception:
            raise SecretNotFoundError("NO/INVALID WM:PAGE_COUNT IN XMP")

        if page_count == 0:
            return str(secret)

        pages_ok = 0
        with self._open_pdf(pdf) as doc:
            with doc.open_metadata() as xmp:
                for i in range(page_count):
                    salt = _xmp_get_any(xmp, f"p{i}_salt")
                    mac = _xmp_get_any(xmp, f"p{i}_mac")
                    if salt and mac:
                        expected = _hmac_hex(key_b, (str(salt) + str(secret)).encode("utf-8"))
                        if hmac.compare_digest(str(mac), expected):
                            pages_ok += 1

        if pages_ok == 0:
            raise InvalidKeyError("HMAC verification failed on all pages")

        return str(secret)

    def xǁXmpPerPageMethodǁread_secret__mutmut_31(self, pdf: PdfSource, key: str) -> str:
        """Läs tillbaka 'secret' och verifiera per-sida HMAC."""
        key_b = _key_to_bytes(key)

        try:
            with self._open_pdf(pdf) as doc:
                with doc.open_metadata() as xmp:
                    secret = _xmp_get_any(xmp, "secret")
                    page_count_str = _xmp_get_any(xmp, "page_count")
        except Exception as e:
            raise SecretNotFoundError(f"Cannot open PDF to read XMP: {e}")

        if not secret:
            raise SecretNotFoundError("No wm:secret in XMP")
        try:
            page_count = int(str(page_count_str))
        except Exception:
            raise SecretNotFoundError("No/invalid wm:page_count in XMP")

        if page_count != 0:
            return str(secret)

        pages_ok = 0
        with self._open_pdf(pdf) as doc:
            with doc.open_metadata() as xmp:
                for i in range(page_count):
                    salt = _xmp_get_any(xmp, f"p{i}_salt")
                    mac = _xmp_get_any(xmp, f"p{i}_mac")
                    if salt and mac:
                        expected = _hmac_hex(key_b, (str(salt) + str(secret)).encode("utf-8"))
                        if hmac.compare_digest(str(mac), expected):
                            pages_ok += 1

        if pages_ok == 0:
            raise InvalidKeyError("HMAC verification failed on all pages")

        return str(secret)

    def xǁXmpPerPageMethodǁread_secret__mutmut_32(self, pdf: PdfSource, key: str) -> str:
        """Läs tillbaka 'secret' och verifiera per-sida HMAC."""
        key_b = _key_to_bytes(key)

        try:
            with self._open_pdf(pdf) as doc:
                with doc.open_metadata() as xmp:
                    secret = _xmp_get_any(xmp, "secret")
                    page_count_str = _xmp_get_any(xmp, "page_count")
        except Exception as e:
            raise SecretNotFoundError(f"Cannot open PDF to read XMP: {e}")

        if not secret:
            raise SecretNotFoundError("No wm:secret in XMP")
        try:
            page_count = int(str(page_count_str))
        except Exception:
            raise SecretNotFoundError("No/invalid wm:page_count in XMP")

        if page_count == 1:
            return str(secret)

        pages_ok = 0
        with self._open_pdf(pdf) as doc:
            with doc.open_metadata() as xmp:
                for i in range(page_count):
                    salt = _xmp_get_any(xmp, f"p{i}_salt")
                    mac = _xmp_get_any(xmp, f"p{i}_mac")
                    if salt and mac:
                        expected = _hmac_hex(key_b, (str(salt) + str(secret)).encode("utf-8"))
                        if hmac.compare_digest(str(mac), expected):
                            pages_ok += 1

        if pages_ok == 0:
            raise InvalidKeyError("HMAC verification failed on all pages")

        return str(secret)

    def xǁXmpPerPageMethodǁread_secret__mutmut_33(self, pdf: PdfSource, key: str) -> str:
        """Läs tillbaka 'secret' och verifiera per-sida HMAC."""
        key_b = _key_to_bytes(key)

        try:
            with self._open_pdf(pdf) as doc:
                with doc.open_metadata() as xmp:
                    secret = _xmp_get_any(xmp, "secret")
                    page_count_str = _xmp_get_any(xmp, "page_count")
        except Exception as e:
            raise SecretNotFoundError(f"Cannot open PDF to read XMP: {e}")

        if not secret:
            raise SecretNotFoundError("No wm:secret in XMP")
        try:
            page_count = int(str(page_count_str))
        except Exception:
            raise SecretNotFoundError("No/invalid wm:page_count in XMP")

        if page_count == 0:
            return str(None)

        pages_ok = 0
        with self._open_pdf(pdf) as doc:
            with doc.open_metadata() as xmp:
                for i in range(page_count):
                    salt = _xmp_get_any(xmp, f"p{i}_salt")
                    mac = _xmp_get_any(xmp, f"p{i}_mac")
                    if salt and mac:
                        expected = _hmac_hex(key_b, (str(salt) + str(secret)).encode("utf-8"))
                        if hmac.compare_digest(str(mac), expected):
                            pages_ok += 1

        if pages_ok == 0:
            raise InvalidKeyError("HMAC verification failed on all pages")

        return str(secret)

    def xǁXmpPerPageMethodǁread_secret__mutmut_34(self, pdf: PdfSource, key: str) -> str:
        """Läs tillbaka 'secret' och verifiera per-sida HMAC."""
        key_b = _key_to_bytes(key)

        try:
            with self._open_pdf(pdf) as doc:
                with doc.open_metadata() as xmp:
                    secret = _xmp_get_any(xmp, "secret")
                    page_count_str = _xmp_get_any(xmp, "page_count")
        except Exception as e:
            raise SecretNotFoundError(f"Cannot open PDF to read XMP: {e}")

        if not secret:
            raise SecretNotFoundError("No wm:secret in XMP")
        try:
            page_count = int(str(page_count_str))
        except Exception:
            raise SecretNotFoundError("No/invalid wm:page_count in XMP")

        if page_count == 0:
            return str(secret)

        pages_ok = None
        with self._open_pdf(pdf) as doc:
            with doc.open_metadata() as xmp:
                for i in range(page_count):
                    salt = _xmp_get_any(xmp, f"p{i}_salt")
                    mac = _xmp_get_any(xmp, f"p{i}_mac")
                    if salt and mac:
                        expected = _hmac_hex(key_b, (str(salt) + str(secret)).encode("utf-8"))
                        if hmac.compare_digest(str(mac), expected):
                            pages_ok += 1

        if pages_ok == 0:
            raise InvalidKeyError("HMAC verification failed on all pages")

        return str(secret)

    def xǁXmpPerPageMethodǁread_secret__mutmut_35(self, pdf: PdfSource, key: str) -> str:
        """Läs tillbaka 'secret' och verifiera per-sida HMAC."""
        key_b = _key_to_bytes(key)

        try:
            with self._open_pdf(pdf) as doc:
                with doc.open_metadata() as xmp:
                    secret = _xmp_get_any(xmp, "secret")
                    page_count_str = _xmp_get_any(xmp, "page_count")
        except Exception as e:
            raise SecretNotFoundError(f"Cannot open PDF to read XMP: {e}")

        if not secret:
            raise SecretNotFoundError("No wm:secret in XMP")
        try:
            page_count = int(str(page_count_str))
        except Exception:
            raise SecretNotFoundError("No/invalid wm:page_count in XMP")

        if page_count == 0:
            return str(secret)

        pages_ok = 1
        with self._open_pdf(pdf) as doc:
            with doc.open_metadata() as xmp:
                for i in range(page_count):
                    salt = _xmp_get_any(xmp, f"p{i}_salt")
                    mac = _xmp_get_any(xmp, f"p{i}_mac")
                    if salt and mac:
                        expected = _hmac_hex(key_b, (str(salt) + str(secret)).encode("utf-8"))
                        if hmac.compare_digest(str(mac), expected):
                            pages_ok += 1

        if pages_ok == 0:
            raise InvalidKeyError("HMAC verification failed on all pages")

        return str(secret)

    def xǁXmpPerPageMethodǁread_secret__mutmut_36(self, pdf: PdfSource, key: str) -> str:
        """Läs tillbaka 'secret' och verifiera per-sida HMAC."""
        key_b = _key_to_bytes(key)

        try:
            with self._open_pdf(pdf) as doc:
                with doc.open_metadata() as xmp:
                    secret = _xmp_get_any(xmp, "secret")
                    page_count_str = _xmp_get_any(xmp, "page_count")
        except Exception as e:
            raise SecretNotFoundError(f"Cannot open PDF to read XMP: {e}")

        if not secret:
            raise SecretNotFoundError("No wm:secret in XMP")
        try:
            page_count = int(str(page_count_str))
        except Exception:
            raise SecretNotFoundError("No/invalid wm:page_count in XMP")

        if page_count == 0:
            return str(secret)

        pages_ok = 0
        with self._open_pdf(None) as doc:
            with doc.open_metadata() as xmp:
                for i in range(page_count):
                    salt = _xmp_get_any(xmp, f"p{i}_salt")
                    mac = _xmp_get_any(xmp, f"p{i}_mac")
                    if salt and mac:
                        expected = _hmac_hex(key_b, (str(salt) + str(secret)).encode("utf-8"))
                        if hmac.compare_digest(str(mac), expected):
                            pages_ok += 1

        if pages_ok == 0:
            raise InvalidKeyError("HMAC verification failed on all pages")

        return str(secret)

    def xǁXmpPerPageMethodǁread_secret__mutmut_37(self, pdf: PdfSource, key: str) -> str:
        """Läs tillbaka 'secret' och verifiera per-sida HMAC."""
        key_b = _key_to_bytes(key)

        try:
            with self._open_pdf(pdf) as doc:
                with doc.open_metadata() as xmp:
                    secret = _xmp_get_any(xmp, "secret")
                    page_count_str = _xmp_get_any(xmp, "page_count")
        except Exception as e:
            raise SecretNotFoundError(f"Cannot open PDF to read XMP: {e}")

        if not secret:
            raise SecretNotFoundError("No wm:secret in XMP")
        try:
            page_count = int(str(page_count_str))
        except Exception:
            raise SecretNotFoundError("No/invalid wm:page_count in XMP")

        if page_count == 0:
            return str(secret)

        pages_ok = 0
        with self._open_pdf(pdf) as doc:
            with doc.open_metadata() as xmp:
                for i in range(None):
                    salt = _xmp_get_any(xmp, f"p{i}_salt")
                    mac = _xmp_get_any(xmp, f"p{i}_mac")
                    if salt and mac:
                        expected = _hmac_hex(key_b, (str(salt) + str(secret)).encode("utf-8"))
                        if hmac.compare_digest(str(mac), expected):
                            pages_ok += 1

        if pages_ok == 0:
            raise InvalidKeyError("HMAC verification failed on all pages")

        return str(secret)

    def xǁXmpPerPageMethodǁread_secret__mutmut_38(self, pdf: PdfSource, key: str) -> str:
        """Läs tillbaka 'secret' och verifiera per-sida HMAC."""
        key_b = _key_to_bytes(key)

        try:
            with self._open_pdf(pdf) as doc:
                with doc.open_metadata() as xmp:
                    secret = _xmp_get_any(xmp, "secret")
                    page_count_str = _xmp_get_any(xmp, "page_count")
        except Exception as e:
            raise SecretNotFoundError(f"Cannot open PDF to read XMP: {e}")

        if not secret:
            raise SecretNotFoundError("No wm:secret in XMP")
        try:
            page_count = int(str(page_count_str))
        except Exception:
            raise SecretNotFoundError("No/invalid wm:page_count in XMP")

        if page_count == 0:
            return str(secret)

        pages_ok = 0
        with self._open_pdf(pdf) as doc:
            with doc.open_metadata() as xmp:
                for i in range(page_count):
                    salt = None
                    mac = _xmp_get_any(xmp, f"p{i}_mac")
                    if salt and mac:
                        expected = _hmac_hex(key_b, (str(salt) + str(secret)).encode("utf-8"))
                        if hmac.compare_digest(str(mac), expected):
                            pages_ok += 1

        if pages_ok == 0:
            raise InvalidKeyError("HMAC verification failed on all pages")

        return str(secret)

    def xǁXmpPerPageMethodǁread_secret__mutmut_39(self, pdf: PdfSource, key: str) -> str:
        """Läs tillbaka 'secret' och verifiera per-sida HMAC."""
        key_b = _key_to_bytes(key)

        try:
            with self._open_pdf(pdf) as doc:
                with doc.open_metadata() as xmp:
                    secret = _xmp_get_any(xmp, "secret")
                    page_count_str = _xmp_get_any(xmp, "page_count")
        except Exception as e:
            raise SecretNotFoundError(f"Cannot open PDF to read XMP: {e}")

        if not secret:
            raise SecretNotFoundError("No wm:secret in XMP")
        try:
            page_count = int(str(page_count_str))
        except Exception:
            raise SecretNotFoundError("No/invalid wm:page_count in XMP")

        if page_count == 0:
            return str(secret)

        pages_ok = 0
        with self._open_pdf(pdf) as doc:
            with doc.open_metadata() as xmp:
                for i in range(page_count):
                    salt = _xmp_get_any(None, f"p{i}_salt")
                    mac = _xmp_get_any(xmp, f"p{i}_mac")
                    if salt and mac:
                        expected = _hmac_hex(key_b, (str(salt) + str(secret)).encode("utf-8"))
                        if hmac.compare_digest(str(mac), expected):
                            pages_ok += 1

        if pages_ok == 0:
            raise InvalidKeyError("HMAC verification failed on all pages")

        return str(secret)

    def xǁXmpPerPageMethodǁread_secret__mutmut_40(self, pdf: PdfSource, key: str) -> str:
        """Läs tillbaka 'secret' och verifiera per-sida HMAC."""
        key_b = _key_to_bytes(key)

        try:
            with self._open_pdf(pdf) as doc:
                with doc.open_metadata() as xmp:
                    secret = _xmp_get_any(xmp, "secret")
                    page_count_str = _xmp_get_any(xmp, "page_count")
        except Exception as e:
            raise SecretNotFoundError(f"Cannot open PDF to read XMP: {e}")

        if not secret:
            raise SecretNotFoundError("No wm:secret in XMP")
        try:
            page_count = int(str(page_count_str))
        except Exception:
            raise SecretNotFoundError("No/invalid wm:page_count in XMP")

        if page_count == 0:
            return str(secret)

        pages_ok = 0
        with self._open_pdf(pdf) as doc:
            with doc.open_metadata() as xmp:
                for i in range(page_count):
                    salt = _xmp_get_any(xmp, None)
                    mac = _xmp_get_any(xmp, f"p{i}_mac")
                    if salt and mac:
                        expected = _hmac_hex(key_b, (str(salt) + str(secret)).encode("utf-8"))
                        if hmac.compare_digest(str(mac), expected):
                            pages_ok += 1

        if pages_ok == 0:
            raise InvalidKeyError("HMAC verification failed on all pages")

        return str(secret)

    def xǁXmpPerPageMethodǁread_secret__mutmut_41(self, pdf: PdfSource, key: str) -> str:
        """Läs tillbaka 'secret' och verifiera per-sida HMAC."""
        key_b = _key_to_bytes(key)

        try:
            with self._open_pdf(pdf) as doc:
                with doc.open_metadata() as xmp:
                    secret = _xmp_get_any(xmp, "secret")
                    page_count_str = _xmp_get_any(xmp, "page_count")
        except Exception as e:
            raise SecretNotFoundError(f"Cannot open PDF to read XMP: {e}")

        if not secret:
            raise SecretNotFoundError("No wm:secret in XMP")
        try:
            page_count = int(str(page_count_str))
        except Exception:
            raise SecretNotFoundError("No/invalid wm:page_count in XMP")

        if page_count == 0:
            return str(secret)

        pages_ok = 0
        with self._open_pdf(pdf) as doc:
            with doc.open_metadata() as xmp:
                for i in range(page_count):
                    salt = _xmp_get_any(f"p{i}_salt")
                    mac = _xmp_get_any(xmp, f"p{i}_mac")
                    if salt and mac:
                        expected = _hmac_hex(key_b, (str(salt) + str(secret)).encode("utf-8"))
                        if hmac.compare_digest(str(mac), expected):
                            pages_ok += 1

        if pages_ok == 0:
            raise InvalidKeyError("HMAC verification failed on all pages")

        return str(secret)

    def xǁXmpPerPageMethodǁread_secret__mutmut_42(self, pdf: PdfSource, key: str) -> str:
        """Läs tillbaka 'secret' och verifiera per-sida HMAC."""
        key_b = _key_to_bytes(key)

        try:
            with self._open_pdf(pdf) as doc:
                with doc.open_metadata() as xmp:
                    secret = _xmp_get_any(xmp, "secret")
                    page_count_str = _xmp_get_any(xmp, "page_count")
        except Exception as e:
            raise SecretNotFoundError(f"Cannot open PDF to read XMP: {e}")

        if not secret:
            raise SecretNotFoundError("No wm:secret in XMP")
        try:
            page_count = int(str(page_count_str))
        except Exception:
            raise SecretNotFoundError("No/invalid wm:page_count in XMP")

        if page_count == 0:
            return str(secret)

        pages_ok = 0
        with self._open_pdf(pdf) as doc:
            with doc.open_metadata() as xmp:
                for i in range(page_count):
                    salt = _xmp_get_any(xmp, )
                    mac = _xmp_get_any(xmp, f"p{i}_mac")
                    if salt and mac:
                        expected = _hmac_hex(key_b, (str(salt) + str(secret)).encode("utf-8"))
                        if hmac.compare_digest(str(mac), expected):
                            pages_ok += 1

        if pages_ok == 0:
            raise InvalidKeyError("HMAC verification failed on all pages")

        return str(secret)

    def xǁXmpPerPageMethodǁread_secret__mutmut_43(self, pdf: PdfSource, key: str) -> str:
        """Läs tillbaka 'secret' och verifiera per-sida HMAC."""
        key_b = _key_to_bytes(key)

        try:
            with self._open_pdf(pdf) as doc:
                with doc.open_metadata() as xmp:
                    secret = _xmp_get_any(xmp, "secret")
                    page_count_str = _xmp_get_any(xmp, "page_count")
        except Exception as e:
            raise SecretNotFoundError(f"Cannot open PDF to read XMP: {e}")

        if not secret:
            raise SecretNotFoundError("No wm:secret in XMP")
        try:
            page_count = int(str(page_count_str))
        except Exception:
            raise SecretNotFoundError("No/invalid wm:page_count in XMP")

        if page_count == 0:
            return str(secret)

        pages_ok = 0
        with self._open_pdf(pdf) as doc:
            with doc.open_metadata() as xmp:
                for i in range(page_count):
                    salt = _xmp_get_any(xmp, f"p{i}_salt")
                    mac = None
                    if salt and mac:
                        expected = _hmac_hex(key_b, (str(salt) + str(secret)).encode("utf-8"))
                        if hmac.compare_digest(str(mac), expected):
                            pages_ok += 1

        if pages_ok == 0:
            raise InvalidKeyError("HMAC verification failed on all pages")

        return str(secret)

    def xǁXmpPerPageMethodǁread_secret__mutmut_44(self, pdf: PdfSource, key: str) -> str:
        """Läs tillbaka 'secret' och verifiera per-sida HMAC."""
        key_b = _key_to_bytes(key)

        try:
            with self._open_pdf(pdf) as doc:
                with doc.open_metadata() as xmp:
                    secret = _xmp_get_any(xmp, "secret")
                    page_count_str = _xmp_get_any(xmp, "page_count")
        except Exception as e:
            raise SecretNotFoundError(f"Cannot open PDF to read XMP: {e}")

        if not secret:
            raise SecretNotFoundError("No wm:secret in XMP")
        try:
            page_count = int(str(page_count_str))
        except Exception:
            raise SecretNotFoundError("No/invalid wm:page_count in XMP")

        if page_count == 0:
            return str(secret)

        pages_ok = 0
        with self._open_pdf(pdf) as doc:
            with doc.open_metadata() as xmp:
                for i in range(page_count):
                    salt = _xmp_get_any(xmp, f"p{i}_salt")
                    mac = _xmp_get_any(None, f"p{i}_mac")
                    if salt and mac:
                        expected = _hmac_hex(key_b, (str(salt) + str(secret)).encode("utf-8"))
                        if hmac.compare_digest(str(mac), expected):
                            pages_ok += 1

        if pages_ok == 0:
            raise InvalidKeyError("HMAC verification failed on all pages")

        return str(secret)

    def xǁXmpPerPageMethodǁread_secret__mutmut_45(self, pdf: PdfSource, key: str) -> str:
        """Läs tillbaka 'secret' och verifiera per-sida HMAC."""
        key_b = _key_to_bytes(key)

        try:
            with self._open_pdf(pdf) as doc:
                with doc.open_metadata() as xmp:
                    secret = _xmp_get_any(xmp, "secret")
                    page_count_str = _xmp_get_any(xmp, "page_count")
        except Exception as e:
            raise SecretNotFoundError(f"Cannot open PDF to read XMP: {e}")

        if not secret:
            raise SecretNotFoundError("No wm:secret in XMP")
        try:
            page_count = int(str(page_count_str))
        except Exception:
            raise SecretNotFoundError("No/invalid wm:page_count in XMP")

        if page_count == 0:
            return str(secret)

        pages_ok = 0
        with self._open_pdf(pdf) as doc:
            with doc.open_metadata() as xmp:
                for i in range(page_count):
                    salt = _xmp_get_any(xmp, f"p{i}_salt")
                    mac = _xmp_get_any(xmp, None)
                    if salt and mac:
                        expected = _hmac_hex(key_b, (str(salt) + str(secret)).encode("utf-8"))
                        if hmac.compare_digest(str(mac), expected):
                            pages_ok += 1

        if pages_ok == 0:
            raise InvalidKeyError("HMAC verification failed on all pages")

        return str(secret)

    def xǁXmpPerPageMethodǁread_secret__mutmut_46(self, pdf: PdfSource, key: str) -> str:
        """Läs tillbaka 'secret' och verifiera per-sida HMAC."""
        key_b = _key_to_bytes(key)

        try:
            with self._open_pdf(pdf) as doc:
                with doc.open_metadata() as xmp:
                    secret = _xmp_get_any(xmp, "secret")
                    page_count_str = _xmp_get_any(xmp, "page_count")
        except Exception as e:
            raise SecretNotFoundError(f"Cannot open PDF to read XMP: {e}")

        if not secret:
            raise SecretNotFoundError("No wm:secret in XMP")
        try:
            page_count = int(str(page_count_str))
        except Exception:
            raise SecretNotFoundError("No/invalid wm:page_count in XMP")

        if page_count == 0:
            return str(secret)

        pages_ok = 0
        with self._open_pdf(pdf) as doc:
            with doc.open_metadata() as xmp:
                for i in range(page_count):
                    salt = _xmp_get_any(xmp, f"p{i}_salt")
                    mac = _xmp_get_any(f"p{i}_mac")
                    if salt and mac:
                        expected = _hmac_hex(key_b, (str(salt) + str(secret)).encode("utf-8"))
                        if hmac.compare_digest(str(mac), expected):
                            pages_ok += 1

        if pages_ok == 0:
            raise InvalidKeyError("HMAC verification failed on all pages")

        return str(secret)

    def xǁXmpPerPageMethodǁread_secret__mutmut_47(self, pdf: PdfSource, key: str) -> str:
        """Läs tillbaka 'secret' och verifiera per-sida HMAC."""
        key_b = _key_to_bytes(key)

        try:
            with self._open_pdf(pdf) as doc:
                with doc.open_metadata() as xmp:
                    secret = _xmp_get_any(xmp, "secret")
                    page_count_str = _xmp_get_any(xmp, "page_count")
        except Exception as e:
            raise SecretNotFoundError(f"Cannot open PDF to read XMP: {e}")

        if not secret:
            raise SecretNotFoundError("No wm:secret in XMP")
        try:
            page_count = int(str(page_count_str))
        except Exception:
            raise SecretNotFoundError("No/invalid wm:page_count in XMP")

        if page_count == 0:
            return str(secret)

        pages_ok = 0
        with self._open_pdf(pdf) as doc:
            with doc.open_metadata() as xmp:
                for i in range(page_count):
                    salt = _xmp_get_any(xmp, f"p{i}_salt")
                    mac = _xmp_get_any(xmp, )
                    if salt and mac:
                        expected = _hmac_hex(key_b, (str(salt) + str(secret)).encode("utf-8"))
                        if hmac.compare_digest(str(mac), expected):
                            pages_ok += 1

        if pages_ok == 0:
            raise InvalidKeyError("HMAC verification failed on all pages")

        return str(secret)

    def xǁXmpPerPageMethodǁread_secret__mutmut_48(self, pdf: PdfSource, key: str) -> str:
        """Läs tillbaka 'secret' och verifiera per-sida HMAC."""
        key_b = _key_to_bytes(key)

        try:
            with self._open_pdf(pdf) as doc:
                with doc.open_metadata() as xmp:
                    secret = _xmp_get_any(xmp, "secret")
                    page_count_str = _xmp_get_any(xmp, "page_count")
        except Exception as e:
            raise SecretNotFoundError(f"Cannot open PDF to read XMP: {e}")

        if not secret:
            raise SecretNotFoundError("No wm:secret in XMP")
        try:
            page_count = int(str(page_count_str))
        except Exception:
            raise SecretNotFoundError("No/invalid wm:page_count in XMP")

        if page_count == 0:
            return str(secret)

        pages_ok = 0
        with self._open_pdf(pdf) as doc:
            with doc.open_metadata() as xmp:
                for i in range(page_count):
                    salt = _xmp_get_any(xmp, f"p{i}_salt")
                    mac = _xmp_get_any(xmp, f"p{i}_mac")
                    if salt or mac:
                        expected = _hmac_hex(key_b, (str(salt) + str(secret)).encode("utf-8"))
                        if hmac.compare_digest(str(mac), expected):
                            pages_ok += 1

        if pages_ok == 0:
            raise InvalidKeyError("HMAC verification failed on all pages")

        return str(secret)

    def xǁXmpPerPageMethodǁread_secret__mutmut_49(self, pdf: PdfSource, key: str) -> str:
        """Läs tillbaka 'secret' och verifiera per-sida HMAC."""
        key_b = _key_to_bytes(key)

        try:
            with self._open_pdf(pdf) as doc:
                with doc.open_metadata() as xmp:
                    secret = _xmp_get_any(xmp, "secret")
                    page_count_str = _xmp_get_any(xmp, "page_count")
        except Exception as e:
            raise SecretNotFoundError(f"Cannot open PDF to read XMP: {e}")

        if not secret:
            raise SecretNotFoundError("No wm:secret in XMP")
        try:
            page_count = int(str(page_count_str))
        except Exception:
            raise SecretNotFoundError("No/invalid wm:page_count in XMP")

        if page_count == 0:
            return str(secret)

        pages_ok = 0
        with self._open_pdf(pdf) as doc:
            with doc.open_metadata() as xmp:
                for i in range(page_count):
                    salt = _xmp_get_any(xmp, f"p{i}_salt")
                    mac = _xmp_get_any(xmp, f"p{i}_mac")
                    if salt and mac:
                        expected = None
                        if hmac.compare_digest(str(mac), expected):
                            pages_ok += 1

        if pages_ok == 0:
            raise InvalidKeyError("HMAC verification failed on all pages")

        return str(secret)

    def xǁXmpPerPageMethodǁread_secret__mutmut_50(self, pdf: PdfSource, key: str) -> str:
        """Läs tillbaka 'secret' och verifiera per-sida HMAC."""
        key_b = _key_to_bytes(key)

        try:
            with self._open_pdf(pdf) as doc:
                with doc.open_metadata() as xmp:
                    secret = _xmp_get_any(xmp, "secret")
                    page_count_str = _xmp_get_any(xmp, "page_count")
        except Exception as e:
            raise SecretNotFoundError(f"Cannot open PDF to read XMP: {e}")

        if not secret:
            raise SecretNotFoundError("No wm:secret in XMP")
        try:
            page_count = int(str(page_count_str))
        except Exception:
            raise SecretNotFoundError("No/invalid wm:page_count in XMP")

        if page_count == 0:
            return str(secret)

        pages_ok = 0
        with self._open_pdf(pdf) as doc:
            with doc.open_metadata() as xmp:
                for i in range(page_count):
                    salt = _xmp_get_any(xmp, f"p{i}_salt")
                    mac = _xmp_get_any(xmp, f"p{i}_mac")
                    if salt and mac:
                        expected = _hmac_hex(None, (str(salt) + str(secret)).encode("utf-8"))
                        if hmac.compare_digest(str(mac), expected):
                            pages_ok += 1

        if pages_ok == 0:
            raise InvalidKeyError("HMAC verification failed on all pages")

        return str(secret)

    def xǁXmpPerPageMethodǁread_secret__mutmut_51(self, pdf: PdfSource, key: str) -> str:
        """Läs tillbaka 'secret' och verifiera per-sida HMAC."""
        key_b = _key_to_bytes(key)

        try:
            with self._open_pdf(pdf) as doc:
                with doc.open_metadata() as xmp:
                    secret = _xmp_get_any(xmp, "secret")
                    page_count_str = _xmp_get_any(xmp, "page_count")
        except Exception as e:
            raise SecretNotFoundError(f"Cannot open PDF to read XMP: {e}")

        if not secret:
            raise SecretNotFoundError("No wm:secret in XMP")
        try:
            page_count = int(str(page_count_str))
        except Exception:
            raise SecretNotFoundError("No/invalid wm:page_count in XMP")

        if page_count == 0:
            return str(secret)

        pages_ok = 0
        with self._open_pdf(pdf) as doc:
            with doc.open_metadata() as xmp:
                for i in range(page_count):
                    salt = _xmp_get_any(xmp, f"p{i}_salt")
                    mac = _xmp_get_any(xmp, f"p{i}_mac")
                    if salt and mac:
                        expected = _hmac_hex(key_b, None)
                        if hmac.compare_digest(str(mac), expected):
                            pages_ok += 1

        if pages_ok == 0:
            raise InvalidKeyError("HMAC verification failed on all pages")

        return str(secret)

    def xǁXmpPerPageMethodǁread_secret__mutmut_52(self, pdf: PdfSource, key: str) -> str:
        """Läs tillbaka 'secret' och verifiera per-sida HMAC."""
        key_b = _key_to_bytes(key)

        try:
            with self._open_pdf(pdf) as doc:
                with doc.open_metadata() as xmp:
                    secret = _xmp_get_any(xmp, "secret")
                    page_count_str = _xmp_get_any(xmp, "page_count")
        except Exception as e:
            raise SecretNotFoundError(f"Cannot open PDF to read XMP: {e}")

        if not secret:
            raise SecretNotFoundError("No wm:secret in XMP")
        try:
            page_count = int(str(page_count_str))
        except Exception:
            raise SecretNotFoundError("No/invalid wm:page_count in XMP")

        if page_count == 0:
            return str(secret)

        pages_ok = 0
        with self._open_pdf(pdf) as doc:
            with doc.open_metadata() as xmp:
                for i in range(page_count):
                    salt = _xmp_get_any(xmp, f"p{i}_salt")
                    mac = _xmp_get_any(xmp, f"p{i}_mac")
                    if salt and mac:
                        expected = _hmac_hex((str(salt) + str(secret)).encode("utf-8"))
                        if hmac.compare_digest(str(mac), expected):
                            pages_ok += 1

        if pages_ok == 0:
            raise InvalidKeyError("HMAC verification failed on all pages")

        return str(secret)

    def xǁXmpPerPageMethodǁread_secret__mutmut_53(self, pdf: PdfSource, key: str) -> str:
        """Läs tillbaka 'secret' och verifiera per-sida HMAC."""
        key_b = _key_to_bytes(key)

        try:
            with self._open_pdf(pdf) as doc:
                with doc.open_metadata() as xmp:
                    secret = _xmp_get_any(xmp, "secret")
                    page_count_str = _xmp_get_any(xmp, "page_count")
        except Exception as e:
            raise SecretNotFoundError(f"Cannot open PDF to read XMP: {e}")

        if not secret:
            raise SecretNotFoundError("No wm:secret in XMP")
        try:
            page_count = int(str(page_count_str))
        except Exception:
            raise SecretNotFoundError("No/invalid wm:page_count in XMP")

        if page_count == 0:
            return str(secret)

        pages_ok = 0
        with self._open_pdf(pdf) as doc:
            with doc.open_metadata() as xmp:
                for i in range(page_count):
                    salt = _xmp_get_any(xmp, f"p{i}_salt")
                    mac = _xmp_get_any(xmp, f"p{i}_mac")
                    if salt and mac:
                        expected = _hmac_hex(key_b, )
                        if hmac.compare_digest(str(mac), expected):
                            pages_ok += 1

        if pages_ok == 0:
            raise InvalidKeyError("HMAC verification failed on all pages")

        return str(secret)

    def xǁXmpPerPageMethodǁread_secret__mutmut_54(self, pdf: PdfSource, key: str) -> str:
        """Läs tillbaka 'secret' och verifiera per-sida HMAC."""
        key_b = _key_to_bytes(key)

        try:
            with self._open_pdf(pdf) as doc:
                with doc.open_metadata() as xmp:
                    secret = _xmp_get_any(xmp, "secret")
                    page_count_str = _xmp_get_any(xmp, "page_count")
        except Exception as e:
            raise SecretNotFoundError(f"Cannot open PDF to read XMP: {e}")

        if not secret:
            raise SecretNotFoundError("No wm:secret in XMP")
        try:
            page_count = int(str(page_count_str))
        except Exception:
            raise SecretNotFoundError("No/invalid wm:page_count in XMP")

        if page_count == 0:
            return str(secret)

        pages_ok = 0
        with self._open_pdf(pdf) as doc:
            with doc.open_metadata() as xmp:
                for i in range(page_count):
                    salt = _xmp_get_any(xmp, f"p{i}_salt")
                    mac = _xmp_get_any(xmp, f"p{i}_mac")
                    if salt and mac:
                        expected = _hmac_hex(key_b, (str(salt) + str(secret)).encode(None))
                        if hmac.compare_digest(str(mac), expected):
                            pages_ok += 1

        if pages_ok == 0:
            raise InvalidKeyError("HMAC verification failed on all pages")

        return str(secret)

    def xǁXmpPerPageMethodǁread_secret__mutmut_55(self, pdf: PdfSource, key: str) -> str:
        """Läs tillbaka 'secret' och verifiera per-sida HMAC."""
        key_b = _key_to_bytes(key)

        try:
            with self._open_pdf(pdf) as doc:
                with doc.open_metadata() as xmp:
                    secret = _xmp_get_any(xmp, "secret")
                    page_count_str = _xmp_get_any(xmp, "page_count")
        except Exception as e:
            raise SecretNotFoundError(f"Cannot open PDF to read XMP: {e}")

        if not secret:
            raise SecretNotFoundError("No wm:secret in XMP")
        try:
            page_count = int(str(page_count_str))
        except Exception:
            raise SecretNotFoundError("No/invalid wm:page_count in XMP")

        if page_count == 0:
            return str(secret)

        pages_ok = 0
        with self._open_pdf(pdf) as doc:
            with doc.open_metadata() as xmp:
                for i in range(page_count):
                    salt = _xmp_get_any(xmp, f"p{i}_salt")
                    mac = _xmp_get_any(xmp, f"p{i}_mac")
                    if salt and mac:
                        expected = _hmac_hex(key_b, (str(salt) - str(secret)).encode("utf-8"))
                        if hmac.compare_digest(str(mac), expected):
                            pages_ok += 1

        if pages_ok == 0:
            raise InvalidKeyError("HMAC verification failed on all pages")

        return str(secret)

    def xǁXmpPerPageMethodǁread_secret__mutmut_56(self, pdf: PdfSource, key: str) -> str:
        """Läs tillbaka 'secret' och verifiera per-sida HMAC."""
        key_b = _key_to_bytes(key)

        try:
            with self._open_pdf(pdf) as doc:
                with doc.open_metadata() as xmp:
                    secret = _xmp_get_any(xmp, "secret")
                    page_count_str = _xmp_get_any(xmp, "page_count")
        except Exception as e:
            raise SecretNotFoundError(f"Cannot open PDF to read XMP: {e}")

        if not secret:
            raise SecretNotFoundError("No wm:secret in XMP")
        try:
            page_count = int(str(page_count_str))
        except Exception:
            raise SecretNotFoundError("No/invalid wm:page_count in XMP")

        if page_count == 0:
            return str(secret)

        pages_ok = 0
        with self._open_pdf(pdf) as doc:
            with doc.open_metadata() as xmp:
                for i in range(page_count):
                    salt = _xmp_get_any(xmp, f"p{i}_salt")
                    mac = _xmp_get_any(xmp, f"p{i}_mac")
                    if salt and mac:
                        expected = _hmac_hex(key_b, (str(None) + str(secret)).encode("utf-8"))
                        if hmac.compare_digest(str(mac), expected):
                            pages_ok += 1

        if pages_ok == 0:
            raise InvalidKeyError("HMAC verification failed on all pages")

        return str(secret)

    def xǁXmpPerPageMethodǁread_secret__mutmut_57(self, pdf: PdfSource, key: str) -> str:
        """Läs tillbaka 'secret' och verifiera per-sida HMAC."""
        key_b = _key_to_bytes(key)

        try:
            with self._open_pdf(pdf) as doc:
                with doc.open_metadata() as xmp:
                    secret = _xmp_get_any(xmp, "secret")
                    page_count_str = _xmp_get_any(xmp, "page_count")
        except Exception as e:
            raise SecretNotFoundError(f"Cannot open PDF to read XMP: {e}")

        if not secret:
            raise SecretNotFoundError("No wm:secret in XMP")
        try:
            page_count = int(str(page_count_str))
        except Exception:
            raise SecretNotFoundError("No/invalid wm:page_count in XMP")

        if page_count == 0:
            return str(secret)

        pages_ok = 0
        with self._open_pdf(pdf) as doc:
            with doc.open_metadata() as xmp:
                for i in range(page_count):
                    salt = _xmp_get_any(xmp, f"p{i}_salt")
                    mac = _xmp_get_any(xmp, f"p{i}_mac")
                    if salt and mac:
                        expected = _hmac_hex(key_b, (str(salt) + str(None)).encode("utf-8"))
                        if hmac.compare_digest(str(mac), expected):
                            pages_ok += 1

        if pages_ok == 0:
            raise InvalidKeyError("HMAC verification failed on all pages")

        return str(secret)

    def xǁXmpPerPageMethodǁread_secret__mutmut_58(self, pdf: PdfSource, key: str) -> str:
        """Läs tillbaka 'secret' och verifiera per-sida HMAC."""
        key_b = _key_to_bytes(key)

        try:
            with self._open_pdf(pdf) as doc:
                with doc.open_metadata() as xmp:
                    secret = _xmp_get_any(xmp, "secret")
                    page_count_str = _xmp_get_any(xmp, "page_count")
        except Exception as e:
            raise SecretNotFoundError(f"Cannot open PDF to read XMP: {e}")

        if not secret:
            raise SecretNotFoundError("No wm:secret in XMP")
        try:
            page_count = int(str(page_count_str))
        except Exception:
            raise SecretNotFoundError("No/invalid wm:page_count in XMP")

        if page_count == 0:
            return str(secret)

        pages_ok = 0
        with self._open_pdf(pdf) as doc:
            with doc.open_metadata() as xmp:
                for i in range(page_count):
                    salt = _xmp_get_any(xmp, f"p{i}_salt")
                    mac = _xmp_get_any(xmp, f"p{i}_mac")
                    if salt and mac:
                        expected = _hmac_hex(key_b, (str(salt) + str(secret)).encode("XXutf-8XX"))
                        if hmac.compare_digest(str(mac), expected):
                            pages_ok += 1

        if pages_ok == 0:
            raise InvalidKeyError("HMAC verification failed on all pages")

        return str(secret)

    def xǁXmpPerPageMethodǁread_secret__mutmut_59(self, pdf: PdfSource, key: str) -> str:
        """Läs tillbaka 'secret' och verifiera per-sida HMAC."""
        key_b = _key_to_bytes(key)

        try:
            with self._open_pdf(pdf) as doc:
                with doc.open_metadata() as xmp:
                    secret = _xmp_get_any(xmp, "secret")
                    page_count_str = _xmp_get_any(xmp, "page_count")
        except Exception as e:
            raise SecretNotFoundError(f"Cannot open PDF to read XMP: {e}")

        if not secret:
            raise SecretNotFoundError("No wm:secret in XMP")
        try:
            page_count = int(str(page_count_str))
        except Exception:
            raise SecretNotFoundError("No/invalid wm:page_count in XMP")

        if page_count == 0:
            return str(secret)

        pages_ok = 0
        with self._open_pdf(pdf) as doc:
            with doc.open_metadata() as xmp:
                for i in range(page_count):
                    salt = _xmp_get_any(xmp, f"p{i}_salt")
                    mac = _xmp_get_any(xmp, f"p{i}_mac")
                    if salt and mac:
                        expected = _hmac_hex(key_b, (str(salt) + str(secret)).encode("UTF-8"))
                        if hmac.compare_digest(str(mac), expected):
                            pages_ok += 1

        if pages_ok == 0:
            raise InvalidKeyError("HMAC verification failed on all pages")

        return str(secret)

    def xǁXmpPerPageMethodǁread_secret__mutmut_60(self, pdf: PdfSource, key: str) -> str:
        """Läs tillbaka 'secret' och verifiera per-sida HMAC."""
        key_b = _key_to_bytes(key)

        try:
            with self._open_pdf(pdf) as doc:
                with doc.open_metadata() as xmp:
                    secret = _xmp_get_any(xmp, "secret")
                    page_count_str = _xmp_get_any(xmp, "page_count")
        except Exception as e:
            raise SecretNotFoundError(f"Cannot open PDF to read XMP: {e}")

        if not secret:
            raise SecretNotFoundError("No wm:secret in XMP")
        try:
            page_count = int(str(page_count_str))
        except Exception:
            raise SecretNotFoundError("No/invalid wm:page_count in XMP")

        if page_count == 0:
            return str(secret)

        pages_ok = 0
        with self._open_pdf(pdf) as doc:
            with doc.open_metadata() as xmp:
                for i in range(page_count):
                    salt = _xmp_get_any(xmp, f"p{i}_salt")
                    mac = _xmp_get_any(xmp, f"p{i}_mac")
                    if salt and mac:
                        expected = _hmac_hex(key_b, (str(salt) + str(secret)).encode("utf-8"))
                        if hmac.compare_digest(None, expected):
                            pages_ok += 1

        if pages_ok == 0:
            raise InvalidKeyError("HMAC verification failed on all pages")

        return str(secret)

    def xǁXmpPerPageMethodǁread_secret__mutmut_61(self, pdf: PdfSource, key: str) -> str:
        """Läs tillbaka 'secret' och verifiera per-sida HMAC."""
        key_b = _key_to_bytes(key)

        try:
            with self._open_pdf(pdf) as doc:
                with doc.open_metadata() as xmp:
                    secret = _xmp_get_any(xmp, "secret")
                    page_count_str = _xmp_get_any(xmp, "page_count")
        except Exception as e:
            raise SecretNotFoundError(f"Cannot open PDF to read XMP: {e}")

        if not secret:
            raise SecretNotFoundError("No wm:secret in XMP")
        try:
            page_count = int(str(page_count_str))
        except Exception:
            raise SecretNotFoundError("No/invalid wm:page_count in XMP")

        if page_count == 0:
            return str(secret)

        pages_ok = 0
        with self._open_pdf(pdf) as doc:
            with doc.open_metadata() as xmp:
                for i in range(page_count):
                    salt = _xmp_get_any(xmp, f"p{i}_salt")
                    mac = _xmp_get_any(xmp, f"p{i}_mac")
                    if salt and mac:
                        expected = _hmac_hex(key_b, (str(salt) + str(secret)).encode("utf-8"))
                        if hmac.compare_digest(str(mac), None):
                            pages_ok += 1

        if pages_ok == 0:
            raise InvalidKeyError("HMAC verification failed on all pages")

        return str(secret)

    def xǁXmpPerPageMethodǁread_secret__mutmut_62(self, pdf: PdfSource, key: str) -> str:
        """Läs tillbaka 'secret' och verifiera per-sida HMAC."""
        key_b = _key_to_bytes(key)

        try:
            with self._open_pdf(pdf) as doc:
                with doc.open_metadata() as xmp:
                    secret = _xmp_get_any(xmp, "secret")
                    page_count_str = _xmp_get_any(xmp, "page_count")
        except Exception as e:
            raise SecretNotFoundError(f"Cannot open PDF to read XMP: {e}")

        if not secret:
            raise SecretNotFoundError("No wm:secret in XMP")
        try:
            page_count = int(str(page_count_str))
        except Exception:
            raise SecretNotFoundError("No/invalid wm:page_count in XMP")

        if page_count == 0:
            return str(secret)

        pages_ok = 0
        with self._open_pdf(pdf) as doc:
            with doc.open_metadata() as xmp:
                for i in range(page_count):
                    salt = _xmp_get_any(xmp, f"p{i}_salt")
                    mac = _xmp_get_any(xmp, f"p{i}_mac")
                    if salt and mac:
                        expected = _hmac_hex(key_b, (str(salt) + str(secret)).encode("utf-8"))
                        if hmac.compare_digest(expected):
                            pages_ok += 1

        if pages_ok == 0:
            raise InvalidKeyError("HMAC verification failed on all pages")

        return str(secret)

    def xǁXmpPerPageMethodǁread_secret__mutmut_63(self, pdf: PdfSource, key: str) -> str:
        """Läs tillbaka 'secret' och verifiera per-sida HMAC."""
        key_b = _key_to_bytes(key)

        try:
            with self._open_pdf(pdf) as doc:
                with doc.open_metadata() as xmp:
                    secret = _xmp_get_any(xmp, "secret")
                    page_count_str = _xmp_get_any(xmp, "page_count")
        except Exception as e:
            raise SecretNotFoundError(f"Cannot open PDF to read XMP: {e}")

        if not secret:
            raise SecretNotFoundError("No wm:secret in XMP")
        try:
            page_count = int(str(page_count_str))
        except Exception:
            raise SecretNotFoundError("No/invalid wm:page_count in XMP")

        if page_count == 0:
            return str(secret)

        pages_ok = 0
        with self._open_pdf(pdf) as doc:
            with doc.open_metadata() as xmp:
                for i in range(page_count):
                    salt = _xmp_get_any(xmp, f"p{i}_salt")
                    mac = _xmp_get_any(xmp, f"p{i}_mac")
                    if salt and mac:
                        expected = _hmac_hex(key_b, (str(salt) + str(secret)).encode("utf-8"))
                        if hmac.compare_digest(str(mac), ):
                            pages_ok += 1

        if pages_ok == 0:
            raise InvalidKeyError("HMAC verification failed on all pages")

        return str(secret)

    def xǁXmpPerPageMethodǁread_secret__mutmut_64(self, pdf: PdfSource, key: str) -> str:
        """Läs tillbaka 'secret' och verifiera per-sida HMAC."""
        key_b = _key_to_bytes(key)

        try:
            with self._open_pdf(pdf) as doc:
                with doc.open_metadata() as xmp:
                    secret = _xmp_get_any(xmp, "secret")
                    page_count_str = _xmp_get_any(xmp, "page_count")
        except Exception as e:
            raise SecretNotFoundError(f"Cannot open PDF to read XMP: {e}")

        if not secret:
            raise SecretNotFoundError("No wm:secret in XMP")
        try:
            page_count = int(str(page_count_str))
        except Exception:
            raise SecretNotFoundError("No/invalid wm:page_count in XMP")

        if page_count == 0:
            return str(secret)

        pages_ok = 0
        with self._open_pdf(pdf) as doc:
            with doc.open_metadata() as xmp:
                for i in range(page_count):
                    salt = _xmp_get_any(xmp, f"p{i}_salt")
                    mac = _xmp_get_any(xmp, f"p{i}_mac")
                    if salt and mac:
                        expected = _hmac_hex(key_b, (str(salt) + str(secret)).encode("utf-8"))
                        if hmac.compare_digest(str(None), expected):
                            pages_ok += 1

        if pages_ok == 0:
            raise InvalidKeyError("HMAC verification failed on all pages")

        return str(secret)

    def xǁXmpPerPageMethodǁread_secret__mutmut_65(self, pdf: PdfSource, key: str) -> str:
        """Läs tillbaka 'secret' och verifiera per-sida HMAC."""
        key_b = _key_to_bytes(key)

        try:
            with self._open_pdf(pdf) as doc:
                with doc.open_metadata() as xmp:
                    secret = _xmp_get_any(xmp, "secret")
                    page_count_str = _xmp_get_any(xmp, "page_count")
        except Exception as e:
            raise SecretNotFoundError(f"Cannot open PDF to read XMP: {e}")

        if not secret:
            raise SecretNotFoundError("No wm:secret in XMP")
        try:
            page_count = int(str(page_count_str))
        except Exception:
            raise SecretNotFoundError("No/invalid wm:page_count in XMP")

        if page_count == 0:
            return str(secret)

        pages_ok = 0
        with self._open_pdf(pdf) as doc:
            with doc.open_metadata() as xmp:
                for i in range(page_count):
                    salt = _xmp_get_any(xmp, f"p{i}_salt")
                    mac = _xmp_get_any(xmp, f"p{i}_mac")
                    if salt and mac:
                        expected = _hmac_hex(key_b, (str(salt) + str(secret)).encode("utf-8"))
                        if hmac.compare_digest(str(mac), expected):
                            pages_ok = 1

        if pages_ok == 0:
            raise InvalidKeyError("HMAC verification failed on all pages")

        return str(secret)

    def xǁXmpPerPageMethodǁread_secret__mutmut_66(self, pdf: PdfSource, key: str) -> str:
        """Läs tillbaka 'secret' och verifiera per-sida HMAC."""
        key_b = _key_to_bytes(key)

        try:
            with self._open_pdf(pdf) as doc:
                with doc.open_metadata() as xmp:
                    secret = _xmp_get_any(xmp, "secret")
                    page_count_str = _xmp_get_any(xmp, "page_count")
        except Exception as e:
            raise SecretNotFoundError(f"Cannot open PDF to read XMP: {e}")

        if not secret:
            raise SecretNotFoundError("No wm:secret in XMP")
        try:
            page_count = int(str(page_count_str))
        except Exception:
            raise SecretNotFoundError("No/invalid wm:page_count in XMP")

        if page_count == 0:
            return str(secret)

        pages_ok = 0
        with self._open_pdf(pdf) as doc:
            with doc.open_metadata() as xmp:
                for i in range(page_count):
                    salt = _xmp_get_any(xmp, f"p{i}_salt")
                    mac = _xmp_get_any(xmp, f"p{i}_mac")
                    if salt and mac:
                        expected = _hmac_hex(key_b, (str(salt) + str(secret)).encode("utf-8"))
                        if hmac.compare_digest(str(mac), expected):
                            pages_ok -= 1

        if pages_ok == 0:
            raise InvalidKeyError("HMAC verification failed on all pages")

        return str(secret)

    def xǁXmpPerPageMethodǁread_secret__mutmut_67(self, pdf: PdfSource, key: str) -> str:
        """Läs tillbaka 'secret' och verifiera per-sida HMAC."""
        key_b = _key_to_bytes(key)

        try:
            with self._open_pdf(pdf) as doc:
                with doc.open_metadata() as xmp:
                    secret = _xmp_get_any(xmp, "secret")
                    page_count_str = _xmp_get_any(xmp, "page_count")
        except Exception as e:
            raise SecretNotFoundError(f"Cannot open PDF to read XMP: {e}")

        if not secret:
            raise SecretNotFoundError("No wm:secret in XMP")
        try:
            page_count = int(str(page_count_str))
        except Exception:
            raise SecretNotFoundError("No/invalid wm:page_count in XMP")

        if page_count == 0:
            return str(secret)

        pages_ok = 0
        with self._open_pdf(pdf) as doc:
            with doc.open_metadata() as xmp:
                for i in range(page_count):
                    salt = _xmp_get_any(xmp, f"p{i}_salt")
                    mac = _xmp_get_any(xmp, f"p{i}_mac")
                    if salt and mac:
                        expected = _hmac_hex(key_b, (str(salt) + str(secret)).encode("utf-8"))
                        if hmac.compare_digest(str(mac), expected):
                            pages_ok += 2

        if pages_ok == 0:
            raise InvalidKeyError("HMAC verification failed on all pages")

        return str(secret)

    def xǁXmpPerPageMethodǁread_secret__mutmut_68(self, pdf: PdfSource, key: str) -> str:
        """Läs tillbaka 'secret' och verifiera per-sida HMAC."""
        key_b = _key_to_bytes(key)

        try:
            with self._open_pdf(pdf) as doc:
                with doc.open_metadata() as xmp:
                    secret = _xmp_get_any(xmp, "secret")
                    page_count_str = _xmp_get_any(xmp, "page_count")
        except Exception as e:
            raise SecretNotFoundError(f"Cannot open PDF to read XMP: {e}")

        if not secret:
            raise SecretNotFoundError("No wm:secret in XMP")
        try:
            page_count = int(str(page_count_str))
        except Exception:
            raise SecretNotFoundError("No/invalid wm:page_count in XMP")

        if page_count == 0:
            return str(secret)

        pages_ok = 0
        with self._open_pdf(pdf) as doc:
            with doc.open_metadata() as xmp:
                for i in range(page_count):
                    salt = _xmp_get_any(xmp, f"p{i}_salt")
                    mac = _xmp_get_any(xmp, f"p{i}_mac")
                    if salt and mac:
                        expected = _hmac_hex(key_b, (str(salt) + str(secret)).encode("utf-8"))
                        if hmac.compare_digest(str(mac), expected):
                            pages_ok += 1

        if pages_ok != 0:
            raise InvalidKeyError("HMAC verification failed on all pages")

        return str(secret)

    def xǁXmpPerPageMethodǁread_secret__mutmut_69(self, pdf: PdfSource, key: str) -> str:
        """Läs tillbaka 'secret' och verifiera per-sida HMAC."""
        key_b = _key_to_bytes(key)

        try:
            with self._open_pdf(pdf) as doc:
                with doc.open_metadata() as xmp:
                    secret = _xmp_get_any(xmp, "secret")
                    page_count_str = _xmp_get_any(xmp, "page_count")
        except Exception as e:
            raise SecretNotFoundError(f"Cannot open PDF to read XMP: {e}")

        if not secret:
            raise SecretNotFoundError("No wm:secret in XMP")
        try:
            page_count = int(str(page_count_str))
        except Exception:
            raise SecretNotFoundError("No/invalid wm:page_count in XMP")

        if page_count == 0:
            return str(secret)

        pages_ok = 0
        with self._open_pdf(pdf) as doc:
            with doc.open_metadata() as xmp:
                for i in range(page_count):
                    salt = _xmp_get_any(xmp, f"p{i}_salt")
                    mac = _xmp_get_any(xmp, f"p{i}_mac")
                    if salt and mac:
                        expected = _hmac_hex(key_b, (str(salt) + str(secret)).encode("utf-8"))
                        if hmac.compare_digest(str(mac), expected):
                            pages_ok += 1

        if pages_ok == 1:
            raise InvalidKeyError("HMAC verification failed on all pages")

        return str(secret)

    def xǁXmpPerPageMethodǁread_secret__mutmut_70(self, pdf: PdfSource, key: str) -> str:
        """Läs tillbaka 'secret' och verifiera per-sida HMAC."""
        key_b = _key_to_bytes(key)

        try:
            with self._open_pdf(pdf) as doc:
                with doc.open_metadata() as xmp:
                    secret = _xmp_get_any(xmp, "secret")
                    page_count_str = _xmp_get_any(xmp, "page_count")
        except Exception as e:
            raise SecretNotFoundError(f"Cannot open PDF to read XMP: {e}")

        if not secret:
            raise SecretNotFoundError("No wm:secret in XMP")
        try:
            page_count = int(str(page_count_str))
        except Exception:
            raise SecretNotFoundError("No/invalid wm:page_count in XMP")

        if page_count == 0:
            return str(secret)

        pages_ok = 0
        with self._open_pdf(pdf) as doc:
            with doc.open_metadata() as xmp:
                for i in range(page_count):
                    salt = _xmp_get_any(xmp, f"p{i}_salt")
                    mac = _xmp_get_any(xmp, f"p{i}_mac")
                    if salt and mac:
                        expected = _hmac_hex(key_b, (str(salt) + str(secret)).encode("utf-8"))
                        if hmac.compare_digest(str(mac), expected):
                            pages_ok += 1

        if pages_ok == 0:
            raise InvalidKeyError(None)

        return str(secret)

    def xǁXmpPerPageMethodǁread_secret__mutmut_71(self, pdf: PdfSource, key: str) -> str:
        """Läs tillbaka 'secret' och verifiera per-sida HMAC."""
        key_b = _key_to_bytes(key)

        try:
            with self._open_pdf(pdf) as doc:
                with doc.open_metadata() as xmp:
                    secret = _xmp_get_any(xmp, "secret")
                    page_count_str = _xmp_get_any(xmp, "page_count")
        except Exception as e:
            raise SecretNotFoundError(f"Cannot open PDF to read XMP: {e}")

        if not secret:
            raise SecretNotFoundError("No wm:secret in XMP")
        try:
            page_count = int(str(page_count_str))
        except Exception:
            raise SecretNotFoundError("No/invalid wm:page_count in XMP")

        if page_count == 0:
            return str(secret)

        pages_ok = 0
        with self._open_pdf(pdf) as doc:
            with doc.open_metadata() as xmp:
                for i in range(page_count):
                    salt = _xmp_get_any(xmp, f"p{i}_salt")
                    mac = _xmp_get_any(xmp, f"p{i}_mac")
                    if salt and mac:
                        expected = _hmac_hex(key_b, (str(salt) + str(secret)).encode("utf-8"))
                        if hmac.compare_digest(str(mac), expected):
                            pages_ok += 1

        if pages_ok == 0:
            raise InvalidKeyError("XXHMAC verification failed on all pagesXX")

        return str(secret)

    def xǁXmpPerPageMethodǁread_secret__mutmut_72(self, pdf: PdfSource, key: str) -> str:
        """Läs tillbaka 'secret' och verifiera per-sida HMAC."""
        key_b = _key_to_bytes(key)

        try:
            with self._open_pdf(pdf) as doc:
                with doc.open_metadata() as xmp:
                    secret = _xmp_get_any(xmp, "secret")
                    page_count_str = _xmp_get_any(xmp, "page_count")
        except Exception as e:
            raise SecretNotFoundError(f"Cannot open PDF to read XMP: {e}")

        if not secret:
            raise SecretNotFoundError("No wm:secret in XMP")
        try:
            page_count = int(str(page_count_str))
        except Exception:
            raise SecretNotFoundError("No/invalid wm:page_count in XMP")

        if page_count == 0:
            return str(secret)

        pages_ok = 0
        with self._open_pdf(pdf) as doc:
            with doc.open_metadata() as xmp:
                for i in range(page_count):
                    salt = _xmp_get_any(xmp, f"p{i}_salt")
                    mac = _xmp_get_any(xmp, f"p{i}_mac")
                    if salt and mac:
                        expected = _hmac_hex(key_b, (str(salt) + str(secret)).encode("utf-8"))
                        if hmac.compare_digest(str(mac), expected):
                            pages_ok += 1

        if pages_ok == 0:
            raise InvalidKeyError("hmac verification failed on all pages")

        return str(secret)

    def xǁXmpPerPageMethodǁread_secret__mutmut_73(self, pdf: PdfSource, key: str) -> str:
        """Läs tillbaka 'secret' och verifiera per-sida HMAC."""
        key_b = _key_to_bytes(key)

        try:
            with self._open_pdf(pdf) as doc:
                with doc.open_metadata() as xmp:
                    secret = _xmp_get_any(xmp, "secret")
                    page_count_str = _xmp_get_any(xmp, "page_count")
        except Exception as e:
            raise SecretNotFoundError(f"Cannot open PDF to read XMP: {e}")

        if not secret:
            raise SecretNotFoundError("No wm:secret in XMP")
        try:
            page_count = int(str(page_count_str))
        except Exception:
            raise SecretNotFoundError("No/invalid wm:page_count in XMP")

        if page_count == 0:
            return str(secret)

        pages_ok = 0
        with self._open_pdf(pdf) as doc:
            with doc.open_metadata() as xmp:
                for i in range(page_count):
                    salt = _xmp_get_any(xmp, f"p{i}_salt")
                    mac = _xmp_get_any(xmp, f"p{i}_mac")
                    if salt and mac:
                        expected = _hmac_hex(key_b, (str(salt) + str(secret)).encode("utf-8"))
                        if hmac.compare_digest(str(mac), expected):
                            pages_ok += 1

        if pages_ok == 0:
            raise InvalidKeyError("HMAC VERIFICATION FAILED ON ALL PAGES")

        return str(secret)

    def xǁXmpPerPageMethodǁread_secret__mutmut_74(self, pdf: PdfSource, key: str) -> str:
        """Läs tillbaka 'secret' och verifiera per-sida HMAC."""
        key_b = _key_to_bytes(key)

        try:
            with self._open_pdf(pdf) as doc:
                with doc.open_metadata() as xmp:
                    secret = _xmp_get_any(xmp, "secret")
                    page_count_str = _xmp_get_any(xmp, "page_count")
        except Exception as e:
            raise SecretNotFoundError(f"Cannot open PDF to read XMP: {e}")

        if not secret:
            raise SecretNotFoundError("No wm:secret in XMP")
        try:
            page_count = int(str(page_count_str))
        except Exception:
            raise SecretNotFoundError("No/invalid wm:page_count in XMP")

        if page_count == 0:
            return str(secret)

        pages_ok = 0
        with self._open_pdf(pdf) as doc:
            with doc.open_metadata() as xmp:
                for i in range(page_count):
                    salt = _xmp_get_any(xmp, f"p{i}_salt")
                    mac = _xmp_get_any(xmp, f"p{i}_mac")
                    if salt and mac:
                        expected = _hmac_hex(key_b, (str(salt) + str(secret)).encode("utf-8"))
                        if hmac.compare_digest(str(mac), expected):
                            pages_ok += 1

        if pages_ok == 0:
            raise InvalidKeyError("HMAC verification failed on all pages")

        return str(None)
    
    xǁXmpPerPageMethodǁread_secret__mutmut_mutants : ClassVar[MutantDict] = {
    'xǁXmpPerPageMethodǁread_secret__mutmut_1': xǁXmpPerPageMethodǁread_secret__mutmut_1, 
        'xǁXmpPerPageMethodǁread_secret__mutmut_2': xǁXmpPerPageMethodǁread_secret__mutmut_2, 
        'xǁXmpPerPageMethodǁread_secret__mutmut_3': xǁXmpPerPageMethodǁread_secret__mutmut_3, 
        'xǁXmpPerPageMethodǁread_secret__mutmut_4': xǁXmpPerPageMethodǁread_secret__mutmut_4, 
        'xǁXmpPerPageMethodǁread_secret__mutmut_5': xǁXmpPerPageMethodǁread_secret__mutmut_5, 
        'xǁXmpPerPageMethodǁread_secret__mutmut_6': xǁXmpPerPageMethodǁread_secret__mutmut_6, 
        'xǁXmpPerPageMethodǁread_secret__mutmut_7': xǁXmpPerPageMethodǁread_secret__mutmut_7, 
        'xǁXmpPerPageMethodǁread_secret__mutmut_8': xǁXmpPerPageMethodǁread_secret__mutmut_8, 
        'xǁXmpPerPageMethodǁread_secret__mutmut_9': xǁXmpPerPageMethodǁread_secret__mutmut_9, 
        'xǁXmpPerPageMethodǁread_secret__mutmut_10': xǁXmpPerPageMethodǁread_secret__mutmut_10, 
        'xǁXmpPerPageMethodǁread_secret__mutmut_11': xǁXmpPerPageMethodǁread_secret__mutmut_11, 
        'xǁXmpPerPageMethodǁread_secret__mutmut_12': xǁXmpPerPageMethodǁread_secret__mutmut_12, 
        'xǁXmpPerPageMethodǁread_secret__mutmut_13': xǁXmpPerPageMethodǁread_secret__mutmut_13, 
        'xǁXmpPerPageMethodǁread_secret__mutmut_14': xǁXmpPerPageMethodǁread_secret__mutmut_14, 
        'xǁXmpPerPageMethodǁread_secret__mutmut_15': xǁXmpPerPageMethodǁread_secret__mutmut_15, 
        'xǁXmpPerPageMethodǁread_secret__mutmut_16': xǁXmpPerPageMethodǁread_secret__mutmut_16, 
        'xǁXmpPerPageMethodǁread_secret__mutmut_17': xǁXmpPerPageMethodǁread_secret__mutmut_17, 
        'xǁXmpPerPageMethodǁread_secret__mutmut_18': xǁXmpPerPageMethodǁread_secret__mutmut_18, 
        'xǁXmpPerPageMethodǁread_secret__mutmut_19': xǁXmpPerPageMethodǁread_secret__mutmut_19, 
        'xǁXmpPerPageMethodǁread_secret__mutmut_20': xǁXmpPerPageMethodǁread_secret__mutmut_20, 
        'xǁXmpPerPageMethodǁread_secret__mutmut_21': xǁXmpPerPageMethodǁread_secret__mutmut_21, 
        'xǁXmpPerPageMethodǁread_secret__mutmut_22': xǁXmpPerPageMethodǁread_secret__mutmut_22, 
        'xǁXmpPerPageMethodǁread_secret__mutmut_23': xǁXmpPerPageMethodǁread_secret__mutmut_23, 
        'xǁXmpPerPageMethodǁread_secret__mutmut_24': xǁXmpPerPageMethodǁread_secret__mutmut_24, 
        'xǁXmpPerPageMethodǁread_secret__mutmut_25': xǁXmpPerPageMethodǁread_secret__mutmut_25, 
        'xǁXmpPerPageMethodǁread_secret__mutmut_26': xǁXmpPerPageMethodǁread_secret__mutmut_26, 
        'xǁXmpPerPageMethodǁread_secret__mutmut_27': xǁXmpPerPageMethodǁread_secret__mutmut_27, 
        'xǁXmpPerPageMethodǁread_secret__mutmut_28': xǁXmpPerPageMethodǁread_secret__mutmut_28, 
        'xǁXmpPerPageMethodǁread_secret__mutmut_29': xǁXmpPerPageMethodǁread_secret__mutmut_29, 
        'xǁXmpPerPageMethodǁread_secret__mutmut_30': xǁXmpPerPageMethodǁread_secret__mutmut_30, 
        'xǁXmpPerPageMethodǁread_secret__mutmut_31': xǁXmpPerPageMethodǁread_secret__mutmut_31, 
        'xǁXmpPerPageMethodǁread_secret__mutmut_32': xǁXmpPerPageMethodǁread_secret__mutmut_32, 
        'xǁXmpPerPageMethodǁread_secret__mutmut_33': xǁXmpPerPageMethodǁread_secret__mutmut_33, 
        'xǁXmpPerPageMethodǁread_secret__mutmut_34': xǁXmpPerPageMethodǁread_secret__mutmut_34, 
        'xǁXmpPerPageMethodǁread_secret__mutmut_35': xǁXmpPerPageMethodǁread_secret__mutmut_35, 
        'xǁXmpPerPageMethodǁread_secret__mutmut_36': xǁXmpPerPageMethodǁread_secret__mutmut_36, 
        'xǁXmpPerPageMethodǁread_secret__mutmut_37': xǁXmpPerPageMethodǁread_secret__mutmut_37, 
        'xǁXmpPerPageMethodǁread_secret__mutmut_38': xǁXmpPerPageMethodǁread_secret__mutmut_38, 
        'xǁXmpPerPageMethodǁread_secret__mutmut_39': xǁXmpPerPageMethodǁread_secret__mutmut_39, 
        'xǁXmpPerPageMethodǁread_secret__mutmut_40': xǁXmpPerPageMethodǁread_secret__mutmut_40, 
        'xǁXmpPerPageMethodǁread_secret__mutmut_41': xǁXmpPerPageMethodǁread_secret__mutmut_41, 
        'xǁXmpPerPageMethodǁread_secret__mutmut_42': xǁXmpPerPageMethodǁread_secret__mutmut_42, 
        'xǁXmpPerPageMethodǁread_secret__mutmut_43': xǁXmpPerPageMethodǁread_secret__mutmut_43, 
        'xǁXmpPerPageMethodǁread_secret__mutmut_44': xǁXmpPerPageMethodǁread_secret__mutmut_44, 
        'xǁXmpPerPageMethodǁread_secret__mutmut_45': xǁXmpPerPageMethodǁread_secret__mutmut_45, 
        'xǁXmpPerPageMethodǁread_secret__mutmut_46': xǁXmpPerPageMethodǁread_secret__mutmut_46, 
        'xǁXmpPerPageMethodǁread_secret__mutmut_47': xǁXmpPerPageMethodǁread_secret__mutmut_47, 
        'xǁXmpPerPageMethodǁread_secret__mutmut_48': xǁXmpPerPageMethodǁread_secret__mutmut_48, 
        'xǁXmpPerPageMethodǁread_secret__mutmut_49': xǁXmpPerPageMethodǁread_secret__mutmut_49, 
        'xǁXmpPerPageMethodǁread_secret__mutmut_50': xǁXmpPerPageMethodǁread_secret__mutmut_50, 
        'xǁXmpPerPageMethodǁread_secret__mutmut_51': xǁXmpPerPageMethodǁread_secret__mutmut_51, 
        'xǁXmpPerPageMethodǁread_secret__mutmut_52': xǁXmpPerPageMethodǁread_secret__mutmut_52, 
        'xǁXmpPerPageMethodǁread_secret__mutmut_53': xǁXmpPerPageMethodǁread_secret__mutmut_53, 
        'xǁXmpPerPageMethodǁread_secret__mutmut_54': xǁXmpPerPageMethodǁread_secret__mutmut_54, 
        'xǁXmpPerPageMethodǁread_secret__mutmut_55': xǁXmpPerPageMethodǁread_secret__mutmut_55, 
        'xǁXmpPerPageMethodǁread_secret__mutmut_56': xǁXmpPerPageMethodǁread_secret__mutmut_56, 
        'xǁXmpPerPageMethodǁread_secret__mutmut_57': xǁXmpPerPageMethodǁread_secret__mutmut_57, 
        'xǁXmpPerPageMethodǁread_secret__mutmut_58': xǁXmpPerPageMethodǁread_secret__mutmut_58, 
        'xǁXmpPerPageMethodǁread_secret__mutmut_59': xǁXmpPerPageMethodǁread_secret__mutmut_59, 
        'xǁXmpPerPageMethodǁread_secret__mutmut_60': xǁXmpPerPageMethodǁread_secret__mutmut_60, 
        'xǁXmpPerPageMethodǁread_secret__mutmut_61': xǁXmpPerPageMethodǁread_secret__mutmut_61, 
        'xǁXmpPerPageMethodǁread_secret__mutmut_62': xǁXmpPerPageMethodǁread_secret__mutmut_62, 
        'xǁXmpPerPageMethodǁread_secret__mutmut_63': xǁXmpPerPageMethodǁread_secret__mutmut_63, 
        'xǁXmpPerPageMethodǁread_secret__mutmut_64': xǁXmpPerPageMethodǁread_secret__mutmut_64, 
        'xǁXmpPerPageMethodǁread_secret__mutmut_65': xǁXmpPerPageMethodǁread_secret__mutmut_65, 
        'xǁXmpPerPageMethodǁread_secret__mutmut_66': xǁXmpPerPageMethodǁread_secret__mutmut_66, 
        'xǁXmpPerPageMethodǁread_secret__mutmut_67': xǁXmpPerPageMethodǁread_secret__mutmut_67, 
        'xǁXmpPerPageMethodǁread_secret__mutmut_68': xǁXmpPerPageMethodǁread_secret__mutmut_68, 
        'xǁXmpPerPageMethodǁread_secret__mutmut_69': xǁXmpPerPageMethodǁread_secret__mutmut_69, 
        'xǁXmpPerPageMethodǁread_secret__mutmut_70': xǁXmpPerPageMethodǁread_secret__mutmut_70, 
        'xǁXmpPerPageMethodǁread_secret__mutmut_71': xǁXmpPerPageMethodǁread_secret__mutmut_71, 
        'xǁXmpPerPageMethodǁread_secret__mutmut_72': xǁXmpPerPageMethodǁread_secret__mutmut_72, 
        'xǁXmpPerPageMethodǁread_secret__mutmut_73': xǁXmpPerPageMethodǁread_secret__mutmut_73, 
        'xǁXmpPerPageMethodǁread_secret__mutmut_74': xǁXmpPerPageMethodǁread_secret__mutmut_74
    }
    
    def read_secret(self, *args, **kwargs):
        result = _mutmut_trampoline(object.__getattribute__(self, "xǁXmpPerPageMethodǁread_secret__mutmut_orig"), object.__getattribute__(self, "xǁXmpPerPageMethodǁread_secret__mutmut_mutants"), args, kwargs, self)
        return result 
    
    read_secret.__signature__ = _mutmut_signature(xǁXmpPerPageMethodǁread_secret__mutmut_orig)
    xǁXmpPerPageMethodǁread_secret__mutmut_orig.__name__ = 'xǁXmpPerPageMethodǁread_secret'

