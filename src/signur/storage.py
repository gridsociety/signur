import hashlib
import os
import uuid
from dataclasses import dataclass
from pathlib import Path

from fastapi import UploadFile

from signur.errors import ApiError


@dataclass(frozen=True)
class StoredUpload:
    key: str
    path: Path
    sha256: str
    size_bytes: int
    prefix: bytes


class LocalBlobStorage:
    def __init__(self, root: Path, max_upload_bytes: int) -> None:
        self.root = root.resolve()
        self.max_upload_bytes = max_upload_bytes
        self.tmp = self.root / ".tmp"
        self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.tmp.mkdir(mode=0o700, parents=True, exist_ok=True)

    def path_for(self, key: str) -> Path:
        if len(key) != 36 or any(char not in "0123456789abcdef-" for char in key):
            raise ValueError("invalid storage key")
        return self.root / key[:2] / key

    def _commit_temporary(self, tmp_path: Path, target: Path) -> None:
        with tmp_path.open("rb+") as output:
            output.flush()
            os.fsync(output.fileno())
        target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.replace(tmp_path, target)
        directory_fd = os.open(target.parent, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)

    async def store_upload(self, upload: UploadFile) -> StoredUpload:
        key = str(uuid.uuid4())
        tmp_path = self.tmp / f"{key}.part"
        target = self.path_for(key)
        digest = hashlib.sha256()
        size = 0
        prefix = bytearray()
        try:
            with tmp_path.open("xb") as output:
                os.chmod(tmp_path, 0o600)
                while chunk := await upload.read(1024 * 1024):
                    size += len(chunk)
                    if size > self.max_upload_bytes:
                        raise ApiError(
                            413,
                            "upload_too_large",
                            f"Il file supera il limite di {self.max_upload_bytes} byte.",
                        )
                    digest.update(chunk)
                    if len(prefix) < 8192:
                        prefix.extend(chunk[: 8192 - len(prefix)])
                    output.write(chunk)
                if size == 0:
                    raise ApiError(422, "empty_upload", "Il file caricato è vuoto.")
            self._commit_temporary(tmp_path, target)
        except Exception:
            tmp_path.unlink(missing_ok=True)
            target.unlink(missing_ok=True)
            raise
        finally:
            await upload.close()
        return StoredUpload(key, target, digest.hexdigest(), size, bytes(prefix))

    def store_bytes(self, data: bytes) -> StoredUpload:
        if not data:
            raise ValueError("cannot store an empty blob")
        key = str(uuid.uuid4())
        tmp_path = self.tmp / f"{key}.part"
        target = self.path_for(key)
        try:
            with tmp_path.open("xb") as output:
                os.chmod(tmp_path, 0o600)
                output.write(data)
            self._commit_temporary(tmp_path, target)
        except Exception:
            tmp_path.unlink(missing_ok=True)
            target.unlink(missing_ok=True)
            raise
        return StoredUpload(
            key=key,
            path=target,
            sha256=hashlib.sha256(data).hexdigest(),
            size_bytes=len(data),
            prefix=data[:8192],
        )

    def delete(self, key: str) -> None:
        self.path_for(key).unlink(missing_ok=True)
