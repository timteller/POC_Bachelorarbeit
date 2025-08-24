import argparse, base64, hashlib, requests
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

BASE_URL = "http://localhost:8000"
KEY_PATH = './keys/client_1.pem'

def load_private_key(path: str) -> Ed25519PrivateKey:
    pem = open(path, "rb").read()
    return serialization.load_pem_private_key(pem, password=None)


def fingerprint(pub_pem: bytes) -> str:
    h = hashes.Hash(hashes.SHA256()); h.update(pub_pem)
    return h.finalize().hex()


def authenticate(priv: Ed25519PrivateKey, fp: str) -> str:
    nonce = requests.post(f"{BASE_URL}/auth/challenge",
                          json={"fingerprint": fp}).json()["nonce"]
    sig64 = base64.b64encode(priv.sign(bytes.fromhex(nonce))).decode()
    r = requests.post(f"{BASE_URL}/auth/verify",
                      json={"fingerprint": fp,
                            "challenge": nonce,
                            "signature": sig64})
    return r.json()["token"]


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def upload(file_path: str, priv: Ed25519PrivateKey, token: str):
    digest = sha256_file(file_path)
    print(f"Hash of {file_path}: {digest}")
    sig64 = base64.b64encode(priv.sign(bytes.fromhex(digest))).decode()
    requests.post(f"{BASE_URL}/artifacts",
                  json={"file_hash": digest, "signature": sig64},
                  headers={"Authorization": f"Bearer {token}"}).raise_for_status()
    print("Upload OK")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("file")
    args = parser.parse_args()

    priv = load_private_key(KEY_PATH)
    pub_pem = priv.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo)
    fp = fingerprint(pub_pem)
    token = authenticate(priv, fp)
    upload(args.file, priv, token)