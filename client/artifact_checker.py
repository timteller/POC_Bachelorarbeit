
from pathlib import Path
import hashlib
import requests
import json
import base64
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization

class ArtifactChecker: 
    def __init__(self, base_url: str = "http://localhost:8000") -> None:
        self.base_url = base_url.rstrip("/")
    
    # Public API -------------------------------------------------------------

    def check(self, file_path: str) -> bool | None:
        digest = self._sha256_file(Path(file_path))
        if digest is None:
            return None
        url = f"{self.base_url}/artifacts/{digest}"
        response = requests.get(url)
        if response.status_code != 200:
            print("ARTIFACT SIGNATURE NOT FOUND")
            return False

        stored_info = response.json()
        if len(stored_info) < 1:
            print("NO SIGNATURE FOUND")
            return False

        stored_info = stored_info[0]
        client_fingerprint = stored_info["client_fingerprint"]
        signature = stored_info["signature"]

        client_info_response = requests.get(f"{self.base_url}/keys/{client_fingerprint}")
        if client_info_response.status_code != 200:
            print("CLIENT INFO NOT FOUND")
            return False

        public_key_pem = client_info_response.json()["public_key_pem"]

        # Signaturprüfung
        try:
            pub_key = serialization.load_pem_public_key(public_key_pem.encode())
            pub_key.verify(base64.b64decode(signature), bytes.fromhex(digest))
            print("SIGNATURE OK")
            return True
        except InvalidSignature:
            print("SIGNATURE INVALID")
            return False

    # Internals --------------------------------------------------------------

    @staticmethod
    def _sha256_file(path: Path) -> str | None:
        h = hashlib.sha256()
        if not path.is_file():
            print(f"[_sha256_file]: File {path} not found")
            return None
        with path.open("rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()