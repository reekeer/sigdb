from __future__ import annotations


class Error(Exception):
    pass


class FormatError(Error):
    pass


class IntegrityError(Error):
    pass
