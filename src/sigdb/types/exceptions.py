from __future__ import annotations


class SigDBError(Exception):
    pass


class SigDBFormatError(SigDBError):
    pass


class SigDBIntegrityError(SigDBError):
    pass


class SigDBSignatureError(SigDBError):
    pass
