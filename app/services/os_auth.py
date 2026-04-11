from __future__ import annotations

from abc import ABC, abstractmethod


class OSAuthProvider(ABC):
    @abstractmethod
    def authenticate(self, username: str, password: str) -> bool:
        raise NotImplementedError


class LocalAuthProvider(OSAuthProvider):
    def authenticate(self, username: str, password: str) -> bool:
        return True


class LinuxPamAuthProvider(OSAuthProvider):
    def __init__(self) -> None:
        try:
            import pam  # type: ignore
        except Exception as exc:  # pragma: no cover - optional dependency
            raise RuntimeError("python-pam is not installed") from exc
        self._pam = pam

    def authenticate(self, username: str, password: str) -> bool:
        return bool(self._pam.pam().authenticate(username, password))
