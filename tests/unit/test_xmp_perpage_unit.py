# tests/unit/test_xmp_perpage_unit.py
import io, hmac, hashlib, binascii, pytest, pikepdf
import plugins.xmp_perpage as xmp
from plugins.xmp_perpage import XmpPerPageMethod
from watermarking_method import InvalidKeyError, SecretNotFoundError

# ------- hjälp-PDF -------
def _n_page_pdf_bytes(n: int) -> bytes:
    b = io.BytesIO()
    with pikepdf.new() as pdf:
        for _ in range(max(0, n)): pdf.add_blank_page()
        pdf.save(b)
    return b.getvalue()

def _one_page_pdf_bytes() -> bytes: return _n_page_pdf_bytes(1)

# ------- helpers -------
def test_key_to_bytes_and_strict_errors():
    k = xmp._key_to_bytes("abc")
    assert isinstance(k, bytes) and len(k) == 32 and xmp._key_to_bytes("abc") == k
    with pytest.raises(ValueError) as ei:
        xmp._key_to_bytes("")
    assert str(ei.value) == "key must be non-empty"
    class FakeKey:
        seen=None
        def encode(self, enc, errors="strict"):
            FakeKey.seen=errors; return b"x"
    assert isinstance(xmp._key_to_bytes(FakeKey()), (bytes, bytearray))
    assert FakeKey.seen == "strict"

def test_hmac_hex_matches_hashlib():
    key, data = b"k", b"data"
    assert xmp._hmac_hex(key, data) == hmac.new(key, data, hashlib.sha256).hexdigest()

# ------- _xmp_get_any: vägar + prioritet -------
def test_xmp_get_any_real_metadata_variants_and_suffix(tmp_path):
    p = tmp_path / "x.pdf"
    with pikepdf.new() as pdf: pdf.add_blank_page(); pdf.save(p)
    with pikepdf.open(p) as doc:
        with doc.open_metadata(set_pikepdf_as_editor=False) as meta:
            try: meta.register_namespace("wm", "https://tatou.local/wm/1.0/")
            except Exception: pass
            meta["{https://tatou.local/wm/1.0/}secret"]="abc"
            assert xmp._xmp_get_any(meta,"secret")=="abc"
            del meta["{https://tatou.local/wm/1.0/}secret"]
            meta["secret"]="zzz"
            assert xmp._xmp_get_any(meta,"secret")=="zzz"
            meta["xx:page_count"]="1"
            assert xmp._xmp_get_any(meta,"page_count")=="1"
            del meta["xx:page_count"]
            assert xmp._xmp_get_any(meta,"page_count") is None

def test_xmp_get_any_priority_enforced_with_guard():
    NS = "https://tatou.local/wm/1.0/"
    class GuardMeta:
        def __init__(self): self.calls=[]
        def get(self, key):
            self.calls.append(key)
            if key == "wm:secret": return None
            if key == f"{{{NS}}}secret": return "URI"   
            if key == "secret": raise AssertionError("plain reached after URI")
        def keys(self): raise AssertionError("suffix loop reached")
    assert xmp._xmp_get_any(GuardMeta(),"secret")=="URI"

def test_xmp_get_any_suffix_loop_or_not_and():
    class SuffixMeta:
        def __init__(self): self._d={"xx:token":"OK"}
        def get(self,k): return None
        def __getitem__(self,k): return self._d[k]
        def keys(self): return list(self._d.keys())
    assert xmp._xmp_get_any(SuffixMeta(),"token")=="OK"

# ------- _write_xmp: namespace/nycklar + flagga (fake) -------
def test__write_xmp_uses_expected_namespace_and_keys_and_flag():
    class FakeMeta:
        def __init__(self): self.reg=[]; self.set=[]
        def register_namespace(self,p,u): self.reg.append((p,u))
        def __setitem__(self,k,v): self.set.append((k,v))
        def __enter__(self): return self
        def __exit__(self,*a): pass
    class MetaCM:
        def __init__(self,h): self.h=h; self.meta=FakeMeta(); h.meta=self.meta
        def __enter__(self): return self.meta
        def __exit__(self,*a): pass
    class FakeDoc:
        def __init__(self): self.pages=[None]; self.flags=[]
        def open_metadata(self,set_pikepdf_as_editor=False):
            self.flags.append(set_pikepdf_as_editor); return MetaCM(self)
    m = XmpPerPageMethod(); d = FakeDoc()
    m._write_xmp(d,"s", xmp._key_to_bytes("k"))
    assert d.flags and d.flags[-1] is False
    assert ("wm","https://tatou.local/wm/1.0/") in d.meta.reg
    keys = {k for (k,_) in d.meta.set}
    for k in ("wm:method","wm:page_count","wm:secret","wm:ts","wm:p0_salt","wm:p0_mac"):
        assert k in keys

# ------- publika metoder -------
def test_is_watermark_applicable_true_false():
    m = XmpPerPageMethod()
    assert m.is_watermark_applicable(_one_page_pdf_bytes()) is True
    assert m.is_watermark_applicable(b"HELLO") is False

def test_add_watermark_roundtrip_and_basic_fields():
    m = XmpPerPageMethod()
    out = m.add_watermark(_one_page_pdf_bytes(),"secret","key")
    assert m.read_secret(out,"key")=="secret"
    with pikepdf.open(io.BytesIO(out)) as doc:
        with doc.open_metadata(set_pikepdf_as_editor=False) as meta:  # <-- ändrat
            assert xmp._xmp_get_any(meta,"method")=="xmp-perpage"
            assert xmp._xmp_get_any(meta,"page_count")=="1"
            assert xmp._xmp_get_any(meta,"secret")=="secret"

def test_invalid_secret_length_bounds_and_messages():
    m = XmpPerPageMethod()
    with pytest.raises(ValueError) as e1: m.add_watermark(_one_page_pdf_bytes(),"","k")
    assert str(e1.value)=="secret must be non-empty"
    m.add_watermark(_one_page_pdf_bytes(),"x"*128,"k")
    with pytest.raises(ValueError) as e2: m.add_watermark(_one_page_pdf_bytes(),"x"*129,"k")
    assert str(e2.value)=="secret too long (max 128 chars)"

def test_open_pdf_bytesio_seeks_to_zero(monkeypatch):
    real = io.BytesIO
    class Spy(real):
        last=None
        def seek(self,off,whence=0):
            Spy.last=(off,whence); return super().seek(off,whence)
    monkeypatch.setattr(xmp.io,"BytesIO",Spy)
    out = XmpPerPageMethod().add_watermark(_one_page_pdf_bytes(),"s","k")
    assert isinstance(out,(bytes,bytearray)) and Spy.last==(0,0)

def test_salt_is_hex_and_hmac_not_called_when_mac_missing(monkeypatch):
    m = XmpPerPageMethod(); data = m.add_watermark(_one_page_pdf_bytes(),"abc123","good")
    with pikepdf.open(io.BytesIO(data)) as doc:
        with doc.open_metadata() as meta:
            salt = xmp._xmp_get_any(meta,"p0_salt")
            assert isinstance(salt,str) and len(salt)==32
            try: binascii.unhexlify(salt.encode("ascii"))
            except Exception: pytest.fail("salt is not valid hex")
    called={"h":False}
    def boom(*a,**k): called["h"]=True; raise AssertionError("HMAC should not run when mac is missing")
    monkeypatch.setattr(xmp,"_hmac_hex",boom)
    buf=io.BytesIO(data)
    with pikepdf.open(buf) as doc:
        with doc.open_metadata(set_pikepdf_as_editor=False) as meta:
            if "{https://tatou.local/wm/1.0/}p0_mac" in meta: del meta["{https://tatou.local/wm/1.0/}p0_mac"]
            elif "wm:p0_mac" in meta: del meta["wm:p0_mac"]
        out=io.BytesIO(); doc.save(out)
    with pytest.raises(InvalidKeyError): m.read_secret(out.getvalue(),"good")
    assert called["h"] is False

def test_missing_secret_and_invalid_page_count_messages():
    m = XmpPerPageMethod(); blank = _one_page_pdf_bytes()
    with pytest.raises(SecretNotFoundError) as e1: m.read_secret(blank,"k")
    assert str(e1.value)=="No wm:secret in XMP"
    b=io.BytesIO(blank)
    with pikepdf.open(b) as doc:
        with doc.open_metadata(set_pikepdf_as_editor=False) as meta:
            meta["{https://tatou.local/wm/1.0/}secret"]="abc"
            meta["{https://tatou.local/wm/1.0/}page_count"]="not-an-int"
        out=io.BytesIO(); doc.save(out); corrupted=out.getvalue()
    with pytest.raises(SecretNotFoundError) as e2: m.read_secret(corrupted,"k")
    assert str(e2.value)=="No/invalid wm:page_count in XMP"

def test_two_pages_wrong_key_fails_all_pages_message():
    m = XmpPerPageMethod()
    out = m.add_watermark(_n_page_pdf_bytes(2),"s3cr3t","good")
    with pytest.raises(InvalidKeyError) as ei: m.read_secret(out,"bad")
    assert str(ei.value)=="HMAC verification failed on all pages"

def test_ts_endswith_Z_and_is_list():
    out = XmpPerPageMethod().add_watermark(_one_page_pdf_bytes(),"s","k")
    with pikepdf.open(io.BytesIO(out)) as doc:
        with doc.open_metadata() as meta:
            ts = xmp._xmp_get_any(meta,"ts")
            assert isinstance(ts,list) and len(ts)==1 and isinstance(ts[0],str)
            assert ts[0].endswith("Z")

def test_read_secret_bad_pdf_has_stable_message():
    with pytest.raises(SecretNotFoundError) as e: XmpPerPageMethod().read_secret(b"NOT A PDF","k")
    assert "Cannot open PDF to read XMP:" in str(e.value)

def test_xmp_get_any_prefix_priority_over_uri_and_plain_guard():
    """Prioriteten ska vara: wm:local -> {URI}local -> plain.
    Vi använder en guard som exploderar om fel branch nås.
    """
    NS = "https://tatou.local/wm/1.0/"

    class GuardMeta:
        def get(self, key):
            if key == "wm:secret":                   # 1) prefix ska vinna
                return "PREFIX"
            if key == f"{{{NS}}}secret":            # 2) skulle vara fallback
                raise AssertionError("URI lookup reached despite prefix hit")
            if key == "secret":                     # 3) får aldrig nås här
                raise AssertionError("plain lookup reached despite prefix hit")
        def keys(self):
            raise AssertionError("suffix loop reached despite direct hit")

    assert xmp._xmp_get_any(GuardMeta(), "secret") == "PREFIX"

def test_namespace_roundtrip_values_via_tolerant_getter():
    """Efter add_watermark ska fält gå att läsas via tolerant getter,
    oavsett hur pikepdf råkar rendera nycklarna internt.
    (Namespace-mutanter fångas redan av fake-testet för _write_xmp.)
    """
    out = XmpPerPageMethod().add_watermark(_one_page_pdf_bytes(), "s", "k")
    with pikepdf.open(io.BytesIO(out)) as doc:
        with doc.open_metadata(set_pikepdf_as_editor=False) as meta:
            assert xmp._xmp_get_any(meta, "method") == "xmp-perpage"
            assert xmp._xmp_get_any(meta, "page_count") == "1"
            assert xmp._xmp_get_any(meta, "secret") == "s"
            ts = xmp._xmp_get_any(meta, "ts")
            assert isinstance(ts, list) and len(ts) == 1 and ts[0].endswith("Z")
