"""Exception hierarchy for BinProof.

Everything derives from BinProofError, so callers can catch one type. The
subclasses say *what kind* of problem it was:

  AnalysisLoadError   the analysis cannot be opened at all
  ArtifactError       one file inside an analysis could not be read/parsed
  LookupFailedError   the analysis is fine, but the thing you asked for is not in it
"""

from __future__ import annotations

from pathlib import Path
from typing import Iterable


class BinProofError(Exception):
    """Base class for all BinProof errors."""


# ---- the analysis cannot be opened -------------------------------------

class AnalysisLoadError(BinProofError):
    """The analysis directory cannot be opened."""


class AnalysisNotFoundError(AnalysisLoadError):
    """The analysis directory does not exist."""


class ManifestError(AnalysisLoadError):
    """manifest.json is missing, malformed or invalid."""

    def __init__(self, path, message: str):
        super().__init__("%s: %s" % (path, message))
        self.path = Path(path)


class UnsupportedSchemaError(AnalysisLoadError):
    """The export was produced with a schema version this loader doesn't know."""


class IncompleteAnalysisError(AnalysisLoadError):
    """The extraction did not finish cleanly (manifest.complete is false)."""

    def __init__(self, message: str, failed_steps: Iterable[str] = ()):
        super().__init__(message)
        self.failed_steps = tuple(failed_steps)


# ---- one artifact is unusable --------------------------------------------

class ArtifactError(BinProofError):
    """A single file in the analysis could not be used."""

    def __init__(self, path, message: str):
        super().__init__("%s: %s" % (path, message))
        self.path = Path(path)
        self.detail = message


class MissingArtifactError(ArtifactError):
    """A file the manifest says should exist is not there."""


class ArtifactUnavailableError(ArtifactError):
    """The export step that produces this file failed, so it is not trusted."""


class ArtifactTooLargeError(ArtifactError):
    """The file exceeds the configured size limit."""


class MalformedJSONError(ArtifactError):
    """The file is not valid UTF-8 JSON."""


class SchemaError(ArtifactError):
    """The JSON parsed, but does not have the expected structure."""

    def __init__(self, path, where: str, message: str):
        detail = "%s: %s" % (where, message) if where else message
        super().__init__(path, detail)
        self.where = where


class UnsafePathError(ArtifactError):
    """A path taken from the JSON would point outside the analysis directory."""


# ---- lookups ---------------------------------------------------------------

class LookupFailedError(BinProofError):
    """The requested item is not in this analysis."""


class FunctionNotFoundError(LookupFailedError):
    def __init__(self, address: str, hint: str = ""):
        msg = "no function at %s in this analysis" % address
        super().__init__(msg + (" (%s)" % hint if hint else ""))
        self.address = address


class InvalidAddressError(BinProofError, ValueError):
    """A value could not be interpreted as an address."""


__all__ = [n for n, v in list(globals().items()) if isinstance(v, type) and v.__module__ == __name__]
