import base64
import hashlib
from pathlib import Path
from typing import Optional

import requests
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


class ArtifactUploader:
    """Client für signierte Datei-Uploads gegen das REST-Backend."""

    def __init__(self, key_path: str, base_url: str = "http://localhost:8000") -> None:
        self.base_url = base_url.rstrip("/")
        self._priv = self._load_private_key(Path(key_path))
        self._fingerprint = self._calc_fingerprint(self._priv.public_key())
        self._token: Optional[str] = None

    # Public API -------------------------------------------------------------

    def upload(self, file_path: str) -> None:
        if self._token is None:
            self._authenticate()
        digest = self._sha256_file(Path(file_path))
        sig64 = self._sign_hex(digest)
        r = requests.post(
            f"{self.base_url}/artifacts",
            json={"file_hash": digest, "signature": sig64},
            headers={"Authorization": f"Bearer {self._token}"},
            timeout=30,
        )
        r.raise_for_status()

    # Internals --------------------------------------------------------------

    @staticmethod
    def _load_private_key(path: Path) -> Ed25519PrivateKey:
        return serialization.load_pem_private_key(path.read_bytes(), password=None)

    @staticmethod
    def _calc_fingerprint(pub_key) -> str:
        pub_pem = pub_key.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        h = hashes.Hash(hashes.SHA256())
        h.update(pub_pem)
        return h.finalize().hex()

    def _sign_hex(self, hex_str: str) -> str:
        return base64.b64encode(self._priv.sign(bytes.fromhex(hex_str))).decode()

    @staticmethod
    def _sha256_file(path: Path) -> str:
        h = hashlib.sha256()
        with path.open("rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()

    def _authenticate(self) -> None:
        # challenge
        r = requests.post(
            f"{self.base_url}/auth/challenge",
            json={"fingerprint": self._fingerprint},
            timeout=10,
        )
        r.raise_for_status()
        nonce = r.json()["nonce"]
        # verify
        sig64 = self._sign_hex(nonce)
        r = requests.post(
            f"{self.base_url}/auth/verify",
            json={
                "fingerprint": self._fingerprint,
                "challenge": nonce,
                "signature": sig64,
            },
            timeout=10,
        )
        r.raise_for_status()
        self._token = r.json()["token"]
