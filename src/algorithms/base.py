"""
Abstraktes Interface fuer alle Signatur-Algorithmen.

Damit der Benchmark-Runner alle drei Algorithmen einheitlich aufrufen kann,
muessen sie dasselbe Interface erfuellen - unabhaengig davon, ob sie
stateful (XMSS) oder stateless (ML-DSA, SPHINCS+) sind.
"""
from __future__ import annotations
from abc import ABC, abstractmethod
from dataclasses import dataclass


@dataclass
class KeyPair:
    """Generisches Schluesselpaar.

    Bei stateful-Verfahren (XMSS) enthaelt secret_key implizit den Index.
    Bei stateless-Verfahren ist es ein reiner Schluessel.
    """
    public_key: bytes
    secret_key: bytes
    algorithm: str
    parameter_set: str


class SignatureScheme(ABC):
    """Einheitliches Interface fuer alle drei Verfahren."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Eindeutiger Algorithmus-Name (z.B. 'XMSS-SHA2_10_256')."""

    @property
    @abstractmethod
    def is_stateful(self) -> bool:
        """True bei XMSS, False bei ML-DSA und SPHINCS+."""

    @abstractmethod
    def keygen(self) -> KeyPair:
        """Erzeugt ein neues Schluesselpaar."""

    @abstractmethod
    def sign(self, secret_key: bytes, message: bytes) -> tuple[bytes, bytes]:
        """Signiert eine Nachricht.

        Returns:
            (signature, updated_secret_key)

        Bei stateful-Verfahren ist updated_secret_key != secret_key,
        weil der Index inkrementiert wurde. Bei stateless ist
        updated_secret_key == secret_key.
        """

    @abstractmethod
    def verify(self, public_key: bytes, message: bytes, signature: bytes) -> bool:
        """Verifiziert eine Signatur."""

    @abstractmethod
    def signature_size(self) -> int:
        """Erwartete Signaturgroesse in Bytes (fuer Benchmark-Plots)."""

    @abstractmethod
    def public_key_size(self) -> int:
        """Erwartete Public-Key-Groesse in Bytes."""

    @abstractmethod
    def secret_key_size(self) -> int:
        """Erwartete Secret-Key-Groesse in Bytes."""
