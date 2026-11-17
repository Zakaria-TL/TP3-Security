#!/usr/bin/env python3
"""TP3 - Part B: self-sovereign identity flow (issuer -> holder wallet -> verifier/smart lock).

* DID method: did:key (Ed25519) - resolved locally, no blockchain, no network call.
* Credential: JSON payload signed by the issuer (Ed25519). Every attribute is a SALTED
  COMMITMENT (SHA-256 of [salt, name, value]); only digests are signed (SD-JWT-like idea).
* Selective disclosure: the holder reveals only the chosen (salt, name, value) triples.
* Key binding: the holder signs the verifier's fresh nonce -> a stolen credential is useless.
* Revocation: issuer publishes a SIGNED revocation list; verifier caches it (no per-request call).
"""
import base64
import hashlib
import json
import os
import secrets
import time

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

# ------------------------------------------------------------------ helpers
B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def b58enc(b: bytes) -> str:
    n, s = int.from_bytes(b, "big"), ""
    while n:
        n, r = divmod(n, 58)
        s = B58[r] + s
    return "1" * (len(b) - len(b.lstrip(b"\0"))) + s


def b58dec(s: str) -> bytes:
    n = 0
    for c in s:
        n = n * 58 + B58.index(c)
    body = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return b"\0" * (len(s) - len(s.lstrip("1"))) + body


def b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def canon(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


def sha(b: bytes) -> str:
    return b64u(hashlib.sha256(b).digest())


def did_from_pub(pub: Ed25519PublicKey) -> str:
    raw = pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return "did:key:z" + b58enc(b"\xed\x01" + raw)          # multicodec ed25519-pub = 0xed01


def resolve_did_key(did: str) -> Ed25519PublicKey:
    """Local resolution: the public key IS the identifier (no registry, no issuer call)."""
    if not did.startswith("did:key:z"):
        raise ValueError("unsupported DID method")
    raw = b58dec(did[len("did:key:z"):])
    if raw[:2] != b"\xed\x01":
        raise ValueError("not an Ed25519 did:key")
    return Ed25519PublicKey.from_public_bytes(raw[2:])


def verify_sig(did: str, msg: bytes, sig_b64: str) -> bool:
    pad = "=" * (-len(sig_b64) % 4)
    try:
        resolve_did_key(did).verify(base64.urlsafe_b64decode(sig_b64 + pad), msg)
        return True
    except (InvalidSignature, ValueError, Exception):
        return False


class Identity:
    def __init__(self):
        self.sk = Ed25519PrivateKey.generate()
        self.did = did_from_pub(self.sk.public_key())

    def sign(self, msg: bytes) -> str:
        return b64u(self.sk.sign(msg))


# ------------------------------------------------------------------ roles
class Issuer(Identity):
    """e.g. the municipality."""

    def __init__(self, name="Municipality"):
        super().__init__()
        self.name, self.revoked, self.rl_version = name, set(), 0

    def issue(self, holder_did, attributes: dict, ttl=3600, decoys=2):
        disclosures, digests = {}, []
        for k, v in attributes.items():
            d = b64u(canon([b64u(secrets.token_bytes(16)), k, v]))
            disclosures[k] = d
            digests.append(sha(d.encode()))
        digests += [sha(secrets.token_bytes(16)) for _ in range(decoys)]   # hide attribute count
        secrets.SystemRandom().shuffle(digests)                            # hide attribute order
        now = int(time.time())
        payload = {"iss": self.did, "sub": holder_did, "jti": secrets.token_hex(8),
                   "iat": now, "exp": now + ttl, "_sd": digests, "_sd_alg": "sha-256"}
        return {"payload": payload, "sig": self.sign(canon(payload))}, disclosures

    def revoke(self, jti):
        self.revoked.add(jti)
        self.rl_version += 1

    def revocation_list(self):
        body = {"iss": self.did, "version": self.rl_version, "revoked": sorted(self.revoked)}
        return {"body": body, "sig": self.sign(canon(body))}


class Wallet(Identity):
    """Holder wallet (could run on a Raspberry Pi)."""

    def present(self, credential, disclosures: dict, reveal, nonce, aud):
        chosen = [disclosures[a] for a in reveal if a in disclosures]
        sd_hash = sha(canon([credential, chosen]))
        kb = {"nonce": nonce, "aud": aud, "sd_hash": sd_hash}
        return {"credential": credential, "disclosures": chosen,
                "kb": kb, "kb_sig": self.sign(canon(kb))}


class Verifier:
    def __init__(self, name, trusted_issuers):
        self.name, self.trusted = name, set(trusted_issuers)
        self.rl = None
        self.issuer_contacts = 0           # how many times we had to talk to the issuer
        self.seen_nonces = set()

    def refresh_revocation(self, issuer: Issuer):
        """Periodic (not per-request) download of the signed revocation list."""
        rl = issuer.revocation_list()
        self.issuer_contacts += 1
        if not verify_sig(rl["body"]["iss"], canon(rl["body"]), rl["sig"]):
            raise ValueError("bad revocation list signature")
        self.rl = rl["body"]

    def new_nonce(self):
        n = secrets.token_hex(12)
        self.seen_nonces.add(n)
        return n

    def verify(self, pres, nonce, now=None):
        now = now or int(time.time())
        cred, pl = pres["credential"], pres["credential"]["payload"]
        if pl["iss"] not in self.trusted:
            return False, "untrusted issuer", {}
        if not verify_sig(pl["iss"], canon(pl), cred["sig"]):
            return False, "bad issuer signature", {}
        if now > pl["exp"]:
            return False, "credential expired", {}
        if self.rl and pl["jti"] in self.rl["revoked"]:
            return False, "credential revoked", {}
        revealed = {}
        for d in pres["disclosures"]:
            if sha(d.encode()) not in pl["_sd"]:
                return False, "disclosure not committed by issuer", {}
            pad = "=" * (-len(d) % 4)
            _salt, name, value = json.loads(base64.urlsafe_b64decode(d + pad))
            revealed[name] = value
        kb = pres["kb"]
        if not verify_sig(pl["sub"], canon(kb), pres["kb_sig"]):
            return False, "holder key-binding signature invalid (not the credential owner)", {}
        if kb["aud"] != self.name:
            return False, "wrong audience", {}
        if kb["sd_hash"] != sha(canon([cred, pres["disclosures"]])):
            return False, "presentation modified", {}
        if kb["nonce"] != nonce or nonce not in self.seen_nonces:
            return False, "bad or replayed nonce", {}
        self.seen_nonces.discard(nonce)                      # single use -> replay protection
        return True, "ok", revealed


class SmartLock(Verifier):
    """Opens only if the policy attribute is revealed AND verified. On real hardware,
    replace the print with a GPIO write (LED / relay)."""

    def __init__(self, trusted):
        super().__init__("smart-lock-01", trusted)

    def request_access(self, pres, nonce):
        ok, why, revealed = self.verify(pres, nonce)
        if ok and revealed.get("over_18") is True:
            return "UNLOCKED", why, revealed
        return "DENIED", (why if not ok else "policy: over_18 not proven"), revealed


# ------------------------------------------------------------------ demo / tests
def main(out="outputs"):
    os.makedirs(out, exist_ok=True)
    issuer, alice, mallory = Issuer("City Hall"), Wallet(), Wallet()
    lock = SmartLock([issuer.did])
    attrs = {"name": "Alice Example", "birth_date": "2001-04-12", "over_18": True,
             "resident_of_city": True}
    cred, discl = issuer.issue(alice.did, attrs)
    lock.refresh_revocation(issuer)
    print("Issuer DID :", issuer.did)
    print("Holder DID :", alice.did)
    print("Credential : %d signed digests (4 real + 2 decoys)\n" % len(cred["payload"]["_sd"]))

    results = []

    def case(title, expected, fn):
        res, why, revealed = fn()
        passed = (res == expected)
        results.append({"scenario": title, "expected": expected, "got": res, "reason": why,
                        "verifier_saw": sorted(revealed.keys()), "pass": passed})
        print(f"[{'PASS' if passed else 'FAIL'}] {title:55s} -> {res:8s} ({why}); verifier saw: {sorted(revealed)}")

    # 1 valid + selective disclosure
    def s1():
        n = lock.new_nonce()
        return lock.request_access(alice.present(cred, discl, ["over_18"], n, lock.name), n)
    case("1. valid credential, only 'over_18' disclosed", "UNLOCKED", s1)

    # 2 disclose another attribute
    def s2():
        n = lock.new_nonce()
        return lock.request_access(alice.present(cred, discl, ["over_18", "resident_of_city"], n, lock.name), n)
    case("2. two attributes disclosed (still valid)", "UNLOCKED", s2)

    # 3 holder does not disclose the needed attribute
    def s3():
        n = lock.new_nonce()
        return lock.request_access(alice.present(cred, discl, ["resident_of_city"], n, lock.name), n)
    case("3. policy attribute not disclosed", "DENIED", s3)

    # 4 forged disclosure (holder lies about value)
    def s4():
        n = lock.new_nonce()
        p = alice.present(cred, discl, ["over_18"], n, lock.name)
        fake = b64u(canon([b64u(secrets.token_bytes(16)), "over_18", True]))
        p["disclosures"] = [fake]
        return lock.request_access(p, n)
    case("4. forged disclosure (not committed by issuer)", "DENIED", s4)

    # 5 replay of an old presentation
    old_n = lock.new_nonce()
    old = alice.present(cred, discl, ["over_18"], old_n, lock.name)
    lock.request_access(old, old_n)
    case("5. replay of a previously accepted presentation", "DENIED",
         lambda: lock.request_access(old, old_n))

    # 6 stolen credential used by another wallet
    def s6():
        n = lock.new_nonce()
        return lock.request_access(mallory.present(cred, discl, ["over_18"], n, lock.name), n)
    case("6. stolen credential presented by another holder", "DENIED", s6)

    # 7 untrusted issuer
    rogue = Issuer("Rogue")
    rc, rd = rogue.issue(alice.did, attrs)

    def s7():
        n = lock.new_nonce()
        return lock.request_access(alice.present(rc, rd, ["over_18"], n, lock.name), n)
    case("7. credential from an untrusted issuer", "DENIED", s7)

    # 8 expired
    ec, ed = issuer.issue(alice.did, attrs, ttl=-1)

    def s8():
        n = lock.new_nonce()
        return lock.request_access(alice.present(ec, ed, ["over_18"], n, lock.name), n)
    case("8. expired credential", "DENIED", s8)

    # 9 modified payload (e.g., change subject/expiry)
    def s9():
        n = lock.new_nonce()
        p = alice.present(cred, discl, ["over_18"], n, lock.name)
        p["credential"] = json.loads(json.dumps(cred))
        p["credential"]["payload"]["exp"] += 10**6
        return lock.request_access(p, n)
    case("9. tampered credential payload", "DENIED", s9)

    # 10 revocation
    contacts_before = lock.issuer_contacts
    issuer.revoke(cred["payload"]["jti"])
    lock.refresh_revocation(issuer)                      # verifier syncs list (periodic)
    def s10():
        n = lock.new_nonce()
        return lock.request_access(alice.present(cred, discl, ["over_18"], n, lock.name), n)
    case("10. credential revoked by issuer", "DENIED", s10)

    summary = {"all_passed": all(r["pass"] for r in results),
               "issuer_contacts_total": lock.issuer_contacts,
               "verifications": len(results),
               "note": "issuer is contacted only to refresh the revocation list, not per request"}
    print("\nIssuer contacts by the verifier:", lock.issuer_contacts, "for", len(results), "verifications")
    print("ALL SCENARIOS AS EXPECTED:", summary["all_passed"])
    json.dump({"scenarios": results, "summary": summary}, open(f"{out}/results_part_b.json", "w"), indent=2)
    return summary["all_passed"]


if __name__ == "__main__":
    raise SystemExit(0 if main() else 1)
