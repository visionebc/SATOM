#!/usr/bin/env python3
"""Sign a SATOM update package — runs WHEREVER THE PRIVATE KEY IS.

Signing is deliberately a separate step from building. The build hosts hold no
secret, so they can be any throwaway machine; this tool runs on the maintainer's
own machine, reads an encrypted private key, and writes ``manifest.sig`` into
the package. Nothing about the private key ever touches the fleet.

    # once, on the machine that will own the release key
    python3 sign_update_package.py genkey --out satom-release --comment "Vision EBC release key"
    #   -> satom-release.key  (encrypted, KEEP THIS; back it up offline)
    #   -> satom-release.pub  (publish this; it can only verify)

    # per release
    python3 sign_update_package.py sign dist/satom-update-1.3.6.tar.gz --key satom-release.key

    # anyone, anywhere
    python3 sign_update_package.py verify dist/satom-update-1.3.6.tar.gz --pub satom-release.pub

Key storage: an encrypted PKCS#8 PEM via ``cryptography`` when available (the
recommended form -- the passphrase is what protects the key at rest). A raw
``satom-ed25519-seed`` file is also accepted so a test suite, an air-gapped
recovery, or a fork without ``cryptography`` installed can still sign.
"""
from __future__ import annotations

import argparse
import base64
import getpass
import os
import shutil
import sys
import tarfile
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import update_package as up  # noqa: E402

SEED_TAG = "satom-ed25519-seed"


# ---------------------------------------------------------------------------
# private key at rest
# ---------------------------------------------------------------------------
def _crypto():
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ed25519
        return serialization, ed25519
    except Exception:
        return None, None


def save_private_key(seed: bytes, path: Path, passphrase: str) -> str:
    serialization, ed25519 = _crypto()
    if serialization is None:
        if passphrase:
            raise SystemExit(
                "cryptography is not installed, so the key cannot be encrypted "
                "at rest.\nInstall it (pip install cryptography) or pass "
                "--insecure-plain-key to accept an unencrypted seed file.")
        path.write_text("%s %s\n" % (SEED_TAG, base64.b64encode(seed).decode()))
        os.chmod(path, 0o600)
        return "raw seed (UNENCRYPTED)"
    key = ed25519.Ed25519PrivateKey.from_private_bytes(seed)
    enc = (serialization.BestAvailableEncryption(passphrase.encode())
           if passphrase else serialization.NoEncryption())
    path.write_bytes(key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=enc))
    os.chmod(path, 0o600)
    return "encrypted PKCS#8 PEM" if passphrase else "PKCS#8 PEM (UNENCRYPTED)"


def load_private_seed(path: Path, passphrase: str | None) -> bytes:
    data = path.read_bytes()
    text = data.decode("utf-8", "replace")
    if text.lstrip().startswith(SEED_TAG):
        raw = base64.b64decode(text.split(None, 1)[1].strip(), validate=True)
        if len(raw) != 32:
            raise SystemExit("%s: seed is not 32 bytes" % path)
        return raw
    serialization, _ = _crypto()
    if serialization is None:
        raise SystemExit("%s looks like a PEM key but cryptography is not "
                         "installed to read it." % path)
    if passphrase is None:
        passphrase = getpass.getpass("Passphrase for %s: " % path.name)
    try:
        key = serialization.load_pem_private_key(
            data, password=passphrase.encode() if passphrase else None)
    except Exception as exc:
        raise SystemExit("could not read %s: %s" % (path, exc))
    return key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption())


# ---------------------------------------------------------------------------
# commands
# ---------------------------------------------------------------------------
def cmd_genkey(args) -> int:
    out = Path(args.out)
    key_path, pub_path = Path(str(out) + ".key"), Path(str(out) + ".pub")
    for p in (key_path, pub_path):
        if p.exists() and not args.force:
            raise SystemExit("%s already exists (use --force to overwrite). "
                             "Overwriting a release key orphans every package "
                             "it signed." % p)
    seed = os.urandom(32)
    pub = up.ed25519_public_from_seed(seed)
    passphrase = ""
    if not args.insecure_plain_key:
        passphrase = getpass.getpass("Passphrase for the new private key: ")
        if passphrase != getpass.getpass("Repeat passphrase: "):
            raise SystemExit("passphrases do not match")
        if not passphrase:
            raise SystemExit("an empty passphrase is not encryption; pass "
                             "--insecure-plain-key if that is really intended")
    how = save_private_key(seed, key_path, passphrase)
    pub_path.write_text(up.format_public_key(pub, args.comment))
    print("private key : %s  (%s)" % (key_path, how))
    print("public key  : %s" % pub_path)
    print("fingerprint : %s" % up.key_fingerprint(pub))
    print()
    print("Back up the private key OFFLINE and never copy it to a managed node.")
    print("Publish the .pub: install it into each node's trust store (%s)"
          % up.DEFAULT_TRUST_DIR)
    return 0


def _sign_dir(pkg_dir: Path, seed: bytes) -> str:
    manifest = pkg_dir / "manifest.json"
    if not manifest.exists():
        raise SystemExit("%s has no manifest.json" % pkg_dir)
    sig = up.ed25519_sign(seed, manifest.read_bytes())
    (pkg_dir / "manifest.sig").write_text(base64.b64encode(sig).decode() + "\n")
    return up.key_fingerprint(up.ed25519_public_from_seed(seed))


def cmd_sign(args) -> int:
    target = Path(args.package)
    seed = load_private_seed(Path(args.key), args.passphrase)
    if target.is_dir():
        fp = _sign_dir(target, seed)
        print("signed %s with %s" % (target, fp))
        return 0

    tmp = Path(tempfile.mkdtemp(prefix="satom-sign-"))
    try:
        pkg_dir = up.extract_package(target, tmp)
        fp = _sign_dir(pkg_dir, seed)
        packed = tmp / "packed.tar.gz"
        with tarfile.open(packed, "w:gz") as tf:
            tf.add(pkg_dir, arcname=pkg_dir.name)
        shutil.move(str(packed), str(target))
        print("signed %s with %s" % (target, fp))
        print("sha256 %s" % up.sha256_file(target))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    return 0


def cmd_verify(args) -> int:
    target = Path(args.package)
    tmp = None
    try:
        if target.is_dir():
            pkg_dir = target
        else:
            tmp = Path(tempfile.mkdtemp(prefix="satom-verify-"))
            pkg_dir = up.extract_package(target, tmp)

        if args.pub:
            pub, comment = up.parse_public_key(Path(args.pub).read_text())
            sig_path = pkg_dir / "manifest.sig"
            if not sig_path.exists():
                print("FAIL: package is unsigned")
                return 1
            sig = base64.b64decode(sig_path.read_text().strip(), validate=True)
            if not up.ed25519_verify(pub, (pkg_dir / "manifest.json").read_bytes(), sig):
                print("FAIL: signature does not verify against %s" % args.pub)
                return 1
            manifest = up.read_manifest(pkg_dir)
            problems = up.verify_contents(pkg_dir, manifest)
            if problems:
                for p in problems:
                    print("FAIL: %s" % p)
                return 1
            print("OK  signature verifies against %s (%s)"
                  % (up.key_fingerprint(pub), comment or args.pub))
        else:
            res = up.verify_package(pkg_dir, args.trust_dir)
            manifest = res["manifest"]
            print("OK  signed by %s (%s)" % (res["key"]["fingerprint"],
                                             res["key"]["comment"] or res["key"]["name"]))
        print("    product %s version %s commit %s"
              % (manifest.get("product"), manifest.get("version"),
                 (manifest.get("commit") or "")[:12]))
        print("    %d file(s), python %s"
              % (len(manifest.get("files") or {}),
                 ", ".join(manifest.get("python_tags") or [])))
        return 0
    except up.PackageError as exc:
        print("FAIL: %s" % exc)
        return 1
    finally:
        if tmp:
            shutil.rmtree(tmp, ignore_errors=True)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="cmd", required=True)

    g = sub.add_parser("genkey", help="create a new release keypair")
    g.add_argument("--out", required=True, help="basename for .key/.pub")
    g.add_argument("--comment", default="", help="comment stored in the .pub")
    g.add_argument("--force", action="store_true")
    g.add_argument("--insecure-plain-key", action="store_true",
                   help="store the private key unencrypted (tests only)")
    g.set_defaults(func=cmd_genkey)

    s = sub.add_parser("sign", help="sign a package (directory or .tar.gz)")
    s.add_argument("package")
    s.add_argument("--key", required=True)
    s.add_argument("--passphrase", default=None,
                   help="avoid on a shared machine; prompted when omitted")
    s.set_defaults(func=cmd_sign)

    v = sub.add_parser("verify", help="verify a package")
    v.add_argument("package")
    v.add_argument("--pub", help="verify against ONE public key file")
    v.add_argument("--trust-dir", default=up.DEFAULT_TRUST_DIR)
    v.set_defaults(func=cmd_verify)

    args = ap.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
