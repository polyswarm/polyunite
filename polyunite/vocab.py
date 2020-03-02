from functools import lru_cache
from itertools import chain
import json
import re
from typing import Dict, Mapping, Union

import pkg_resources


class VocabRegex:
    name: str
    fields: Dict[str, Union[Dict, str]]

    def __init__(self, name, fields):
        self.name = name
        self.fields = fields

    @lru_cache(maxsize=32)
    def compile(self, min=0, max=1):
        def driver(group, elt, depth=0):
            result = '|'.join(
                set(
                    chain(
                        elt.get('__alias__', []),
                        (driver(k, elt[k], depth + 1) for k in elt if not k.startswith('__'))
                    ) if isinstance(elt, Mapping) else ()
                ).union({group} if depth else ())
            )
            return fr'(?P<{group}>{result})' if min <= depth <= max and group.isidentifier() else result

        return re.compile(driver(self.name, self.fields), re.IGNORECASE)

    def __str__(self):
        return '(?i:%s)' % self.compile(min=0, max=1).pattern

    @classmethod
    def load_vocab(cls, name):
        return cls(name, json.load(pkg_resources.resource_stream(__name__, f'vocabs/{name.lower()}.json')))


# Provides extra detail about the malware, including how it is used as part of a multicomponent
# threat. In the example above,
LABELS = VocabRegex.load_vocab('LABELS')
LANGS = VocabRegex.load_vocab('LANGS')
ARCHIVES = VocabRegex.load_vocab('ARCHIVES')
MACROS = VocabRegex.load_vocab('MACROS')
OSES = VocabRegex.load_vocab('OPERATING_SYSTEMS')
HEURISTICS = VocabRegex.load_vocab('HEURISTICS')
OBFUSCATIONS = VocabRegex.load_vocab('OBFUSCATIONS')

PLATFORM = rf"{OSES}|{ARCHIVES}|{MACROS}|{LANGS}"
BEHAVIORS = r"(?P<BEHAVIOR>AntiVM)"
IDENT = r"""(?P<NAME> (
                (?P<FAMILY>(((CVE-[\d-]+)|[-\w]+?)(\.\w+(?=(\.\d+)))?))
                ((?P<VARIANTSEP>\.)(?P<VARIANT>\w*))?
                ((?P<SUFFIXSEP>!)(?P<SUFFIX>\w*))?))"""
EXPLOITS = r'(?P<EXPLOIT>(Exploit|Exp))'
