import typing
import base64
import itertools


def force_bytes(s: typing.Union[str, bytes]):
    """Forces an input to bytes"""

    if not isinstance(s, (str, bytes)):
        raise TypeError("input must be of str or bytes")

    if isinstance(s, str):
        return s.encode("utf-8")

    return s


def b64encode(s: typing.Union[str, bytes], urlsafe: bool = True) -> str:
    """Base64 encodes a string or bytes object"""
    inpt = force_bytes(s)
    return (
        base64.urlsafe_b64encode(inpt) if urlsafe else base64.b64encode(inpt)
    ).decode("utf-8")


def static_xor(x: bytes, y: bytes):
    return bytes([_a ^ _b for _a, _b in zip(x, y)])


def string_xor(x: bytes, key):
    return static_xor(x, itertools.cycle((key,)))


def score_string(s: str):
    result = 0
    for x in s:
        if x < 32 or x > 126:
            result += 1

    return result
