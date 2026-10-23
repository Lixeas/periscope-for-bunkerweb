"""Lecture de la version BunkerWeb dans le jeton Biscuit émis par POST /auth, sans dépendance.

Le jeton n'est pas chiffré : la table de symboles du bloc d'autorité contient en clair les valeurs de texte
(nom d'utilisateur, IP, Host, version...). Les noms des faits (user, time, client_ip, domain, version) font
partie de la table par défaut de Biscuit et n'y figurent pas. Schéma Biscuit v3 (schema.proto) :
Biscuit{rootKeyId=1, authority=2: SignedBlock{block=1: Block{symbols=1 (string répété), ...}}}.
Ne lève jamais : toute anomalie renvoie None.
"""
import base64
import binascii
import re

_MAX_DECODED = 64 * 1024
_VERSION_RE = re.compile(r"\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.\-+]*)?")  # 3 composantes : exclut une IPv4


def _fields(buf: bytes):
    """Itère (numéro, type_fil, valeur) ; valeur = int ou bytes. Lève ValueError si malformé."""
    i, n = 0, len(buf)

    def varint() -> int:
        nonlocal i
        shift = result = 0
        while True:
            if i >= n or shift > 63:
                raise ValueError("varint")
            b = buf[i]
            i += 1
            result |= (b & 0x7F) << shift
            if not b & 0x80:
                return result
            shift += 7

    while i < n:
        key = varint()
        num, wt = key >> 3, key & 7
        if wt == 0:
            yield num, wt, varint()
        elif wt == 2:
            ln = varint()
            if ln > n - i:
                raise ValueError("length")
            yield num, wt, buf[i:i + ln]
            i += ln
        elif wt in (1, 5):
            size = 8 if wt == 1 else 4
            if size > n - i:
                raise ValueError("fixed")
            yield num, wt, buf[i:i + size]
            i += size
        else:
            raise ValueError("wire type")


def _first_bytes(buf: bytes, number: int) -> bytes | None:
    for num, wt, val in _fields(buf):
        if num == number and wt == 2:
            return val
    return None


def version_from_token(token: str) -> str | None:
    try:
        if not isinstance(token, str) or not token or len(token) > _MAX_DECODED * 2:
            return None
        s = token.strip().replace("-", "+").replace("_", "/").rstrip("=")
        s += "=" * (-len(s) % 4)
        raw = base64.b64decode(s, validate=True)
        if len(raw) > _MAX_DECODED:
            return None
        signed = _first_bytes(raw, 2)
        block = _first_bytes(signed, 1) if signed is not None else None
        if block is None:
            return None
        for num, wt, val in _fields(block):
            if num == 1 and wt == 2:
                try:
                    sym = val.decode("utf-8")
                except UnicodeDecodeError:
                    continue
                if _VERSION_RE.fullmatch(sym):
                    return sym[:32]
    except (ValueError, binascii.Error, TypeError):
        return None
    return None
