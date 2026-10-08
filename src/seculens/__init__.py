"""SecuLens Python implementation; no JavaScript runtime dependency."""

from .analysis import analyze
from .core import scan_sbom, sha256
from .database import fetch_database, validate_database
from .licenses import evaluate_license
from .matcher import match_record
from .sbom import parse_sbom
from .word import write_word_report

__version__ = "0.3.0"
__all__ = [
    "scan_sbom",
    "sha256",
    "parse_sbom",
    "match_record",
    "evaluate_license",
    "fetch_database",
    "validate_database",
    "analyze",
    "__version__",
    "write_word_report",
]
