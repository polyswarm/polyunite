from functools import lru_cache
from itertools import chain
import json
import re
from typing import Any, Dict, Mapping, Union

import pkg_resources


def group(*choices, fmt='({})'):
    return fmt.format('|'.join(set(str(c) for c in choices if c)))


class VocabRegex:
    name: str
    fields: Dict[str, Union[Dict, str]]

    def __init__(self, name, fields):
        self.name = name
        self.fields = fields

    @lru_cache()
    def compile(self, min=0, max=4):
        def driver(name, elt, depth=0):
            fmt = "(?P<%s>{})" % name if min <= depth <= max and name.isidentifier() else r'{}'
            name = name != self.name and name
            return group(
                name,
                *elt.get('__alias__', ()),
                *(driver(k, v, depth + 1) for k, v in elt.items() if not k.startswith('__')),
                fmt=fmt
            ) if isinstance(elt, Mapping) else group(name, fmt=fmt)

        return re.compile(driver(self.name, self.fields), re.IGNORECASE)

    def __format__(self, spec):
        opts = dict(map(lambda s: re.split(r'=|\Z', s, maxsplit=1), spec.split(':')))
        if 'x' in opts:
            pat = '(?P<{name}>((?:{prefix})?(?:{pattern}))+)'.format(name=self.name,pattern=self.compile(1,1).pattern, prefix=opts.get('x') or r'[-.]')
        else:
            pat = self.compile().pattern
        if '-i' not in opts:
            pat = r'(?i:{})'.format(pat)
        return pat

    @classmethod
    def load_vocab(cls, name, **kwargs):
        return cls(name, json.load(pkg_resources.resource_stream(__name__, f'vocabs/{name.lower()}.json')), **kwargs)


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
IDENT = r"""
    (?P<NAME> (
        (?P<FAMILY>(( (CVE-[\d-]+) | [A-Z]+ | ([A-Z]*[0-9_a-z]+(?:-?))*[A-Z]* ) ))
                ((?P<VARIANTSEP>\.)(?P<VARIANT>([A-Z0-9]*?|[a-z0-9]*?)(\.\w*$)?))?
                ((?P<SUFFIXSEP>!)(?P<SUFFIX>\w+))?
    )
)"""
EXPLOITS = r'(?P<EXPLOIT>(Exploit|Exp))'
