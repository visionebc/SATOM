# tests/test_cert_probe.py
import datetime
from app.services import cert_probe


def _self_signed_pem():
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "shop.example.com")])
    now = datetime.datetime.utcnow()
    cert = (x509.CertificateBuilder()
            .subject_name(name).issuer_name(name)
            .public_key(key.public_key())
            .serial_number(0x1234)
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=30))
            .add_extension(x509.SubjectAlternativeName(
                [x509.DNSName("shop.example.com"), x509.DNSName("www.example.com")]),
                critical=False)
            .sign(key, hashes.SHA256()))
    return cert.public_bytes(serialization.Encoding.PEM).decode()


def test_detail_from_pem_extracts_fields():
    d = cert_probe.detail_from_pem(_self_signed_pem())
    assert d["cn"] == "shop.example.com"
    assert "shop.example.com" in d["sans"] and "www.example.com" in d["sans"]
    assert d["serial"] == "1234"
    assert d["issuer_cn"] == "shop.example.com"
    assert d["days_left"] is not None and 28 <= d["days_left"] <= 30
    assert d["fingerprint_sha256"] and len(d["fingerprint_sha256"]) == 64
    assert d["not_after"] is not None


def test_detail_from_pem_bad_input_is_safe():
    d = cert_probe.detail_from_pem("not a pem")
    assert d["cn"] == "" and d["sans"] == [] and d["days_left"] is None
