"""
Detection-evasion defence (section 2.8): normalise a URL before the model sees it.

The model learned character n-grams from plain-ASCII URLs. Someone could
disguise a link by swapping Latin letters for Cyrillic look-alikes, using
full-width letters, inserting invisible characters or percent-encoding the
hostname. Browsers can still resolve these versions to the same destination,
so the model should analyse the address the browser will use.

The URL is processed in these steps:
  1. Remove invisible characters (zero-width spaces/joiners, BOM, soft hyphen, bidi controls).
  2. Unicode NFKC normalisation (full-width and other compatibility forms -> ASCII).
  3. Percent-decode and lower-case the hostname; decode punycode (xn--) labels.
  4. Map look-alike characters (Cyrillic/Greek homoglyphs) to their Latin skeleton.
  5. Re-encode anything still non-ASCII the way a browser would (punycode host, %-encoded path).

A hostname that uses look-alike letters to imitate another name is flagged as
high risk (see assess.py).
"""

import re
import unicodedata
from dataclasses import dataclass, field
from urllib.parse import quote, unquote

_INVISIBLE_RE = re.compile('[­᠎​-‏‪-‮⁠-⁤⁦-⁩﻿]')

# Characters that can look like Latin letters in common fonts, based on the
# Unicode confusables list (UTS #39). This mapping covers Cyrillic and Greek.
_CONFUSABLES = str.maketrans({
    # Cyrillic lowercase letters
    'а': 'a', 'в': 'b', 'е': 'e', 'ё': 'e', 'һ': 'h', 'і': 'i', 'ї': 'i', 'ј': 'j', 'к': 'k',
    'ӏ': 'l', 'м': 'm', 'н': 'h', 'о': 'o', 'р': 'p', 'ԛ': 'q', 'г': 'r', 'ѕ': 's', 'т': 't',
    'ѵ': 'v', 'ԝ': 'w', 'х': 'x', 'у': 'y', 'ү': 'y', 'с': 'c', 'ԁ': 'd', 'ɡ': 'g',
    # Cyrillic uppercase letters
    'А': 'a', 'В': 'b', 'С': 'c', 'Е': 'e', 'Н': 'h', 'І': 'i', 'Ј': 'j', 'К': 'k', 'М': 'm',
    'О': 'o', 'Р': 'p', 'Ѕ': 's', 'Т': 't', 'Х': 'x', 'У': 'y', 'Ү': 'y', 'Ԝ': 'w',
    # Greek letters
    'α': 'a', 'β': 'b', 'ε': 'e', 'ι': 'i', 'κ': 'k', 'ν': 'v', 'ο': 'o', 'ρ': 'p', 'τ': 't',
    'υ': 'u', 'χ': 'x', 'γ': 'y', 'Α': 'a', 'Β': 'b', 'Ε': 'e', 'Ζ': 'z', 'Η': 'h', 'Ι': 'i',
    'Κ': 'k', 'Μ': 'm', 'Ν': 'n', 'Ο': 'o', 'Ρ': 'p', 'Τ': 't', 'Υ': 'y', 'Χ': 'x',
    # Latin variants that Unicode NFKC doesn't change
    'ı': 'i', 'ȷ': 'j', 'ł': 'l', 'ƚ': 'l', 'ɩ': 'i', 'ꞵ': 'b',
})

_SPLIT_RE = re.compile(r'^(?P<scheme>[A-Za-z][A-Za-z0-9+.-]*://|//)?(?P<authority>[^/?#]*)(?P<rest>.*)$', re.DOTALL)
_PATH_SAFE = "/?#[]@!$&'()*+,;=:%~-._"


@dataclass
class NormalisedUrl:
    url: str
    original: str
    lookalike_host: bool = False   # True when the hostname uses look-alike letters.
    notes: list[dict[str, str]] = field(default_factory=list)

    @property
    def changed(self) -> bool:
        return self.url != self.original


_WORD_RE = re.compile(r'[^\W\d_]+')


def _skeleton_word(word: str) -> str:
    """Convert disguised words to Latin while leaving genuine foreign words alone."""
    mapped = word.translate(_CONFUSABLES)
    if mapped == word:
        return word
    if mapped.isascii() or any(c.isascii() for c in word):
        return mapped
    return word


def _to_skeleton(text: str) -> tuple[str, bool]:
    mapped = _WORD_RE.sub(lambda m: _skeleton_word(m.group()), text)
    return mapped, mapped != text


def _normalise_host(host: str, result: NormalisedUrl) -> str:
    if '%' in host:
        decoded = unquote(host)
        if decoded != host:
            result.notes.append({
                'part': 'hostname', 'text': host,
                'reason': 'The website name is percent-encoded. Browsers decode it, so it was decoded before checking.',
            })
            host = decoded

    labels = []
    for label in host.lower().split('.'):
        if label.startswith('xn--'):
            try:
                decoded = label.encode('ascii').decode('idna')
            except (UnicodeError, ValueError):
                decoded = label
            skeleton, had_lookalikes = _to_skeleton(decoded)
            if had_lookalikes and skeleton.isascii():
                result.lookalike_host = True
                result.notes.append({
                    'part': 'hostname', 'text': label,
                    'reason': f'This punycode label decodes to "{decoded}", which imitates "{skeleton}" using look-alike letters.',
                })
                label = skeleton
        else:
            skeleton, had_lookalikes = _to_skeleton(label)
            if had_lookalikes:
                result.lookalike_host = True
                result.notes.append({
                    'part': 'hostname', 'text': label,
                    'reason': f'This website name uses look-alike letters from another alphabet to imitate "{skeleton}".',
                })
                label = skeleton
            if not label.isascii():
                # Keep genuine international names, encoded as browsers send them.
                try:
                    label = label.encode('idna').decode('ascii')
                except UnicodeError:
                    label = 'xn--' + label.encode('punycode').decode('ascii')
        labels.append(label)
    return '.'.join(labels)


def normalise_url(raw: str) -> NormalisedUrl:
    original = raw.strip()
    result = NormalisedUrl(url=original, original=original)

    text, removed = _INVISIBLE_RE.subn('', original)
    if removed:
        result.notes.append({
            'part': 'hidden characters', 'text': f'{removed} invisible character{"s" if removed != 1 else ""}',
            'reason': 'The address contains invisible characters, which are used to disguise links. They were removed before checking.',
        })

    nfkc = unicodedata.normalize('NFKC', text)
    if nfkc != text:
        result.notes.append({
            'part': 'look-alike characters', 'text': text,
            'reason': 'The address uses stylised characters (such as full-width letters) that browsers treat as ordinary ones.',
        })
        text = nfkc

    match = _SPLIT_RE.match(text)
    scheme, authority, rest = match.group('scheme') or '', match.group('authority'), match.group('rest')

    userinfo, at, hostport = authority.rpartition('@')
    host, port = hostport, ''
    if not hostport.startswith('['):  # IPv6 addresses are already in bracketed form.
        host, colon, port_part = hostport.partition(':')
        port = colon + port_part
    host = _normalise_host(host, result)

    skeleton_rest, rest_lookalikes = _to_skeleton(rest)
    if rest_lookalikes:
        result.notes.append({
            'part': 'path', 'text': rest,
            'reason': 'The rest of the address uses look-alike letters from another alphabet, often to hide words such as "login".',
        })
    rest = quote(skeleton_rest, safe=_PATH_SAFE) if not skeleton_rest.isascii() else skeleton_rest
    userinfo = quote(_to_skeleton(userinfo)[0], safe=_PATH_SAFE) if userinfo else userinfo

    result.url = f'{scheme}{userinfo}{at}{host}{port}{rest}'
    return result
