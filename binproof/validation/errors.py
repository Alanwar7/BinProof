from ..errors import BinProofError


class ValidationInputError(BinProofError):
    """The AI result file, or the data it must be checked against, cannot be used."""
