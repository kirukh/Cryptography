"""Algorithmen-Wrapper fuer XMSS, ML-DSA und SLH-DSA (SPHINCS+)."""
from .base import SignatureScheme, KeyPair
from .mldsa_wrapper import MLDSAScheme
from .sphincs_wrapper import SLHDSAScheme, SPHINCSScheme  # SPHINCSScheme = Alias
from .xmss_wrapper import XMSSScheme, XMSSNotEnabledError

__all__ = [
    "SignatureScheme",
    "KeyPair",
    "MLDSAScheme",
    "SLHDSAScheme",
    "SPHINCSScheme",  # rueckwaertskompatibel
    "XMSSScheme",
    "XMSSNotEnabledError",
]
