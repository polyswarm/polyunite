from functools import lru_cache
from itertools import chain
import json
import re
from typing import Any, Dict, Mapping, Union

import pkg_resources


def group(*choices, fmt=None, name=None):
    spec = fmt or name and fr'(?P<{name}>{{}})' or '(?:{})'
    return spec.format('|'.join(set(map(format, filter(None, choices)))))


class VocabRegex:
    name: str
    fields: Dict[str, Union[Dict, str]]

    def __init__(self, name, fields):
        self.name = name
        self.fields = fields

    @lru_cache()
    def compile(self, min=0, max=4):
        def driver(name, elt, depth=0):
            group_name = min <= depth <= max and name.isidentifier() and name
            name_pattern = None if name == self.name else name
            return group(
                name_pattern,
                *elt.get('__alias__', ()),
                *(driver(k, v, depth + 1) for k, v in elt.items() if not k.startswith('__')),
                name=group_name
            ) if isinstance(elt, Mapping) else group(name_pattern, name=group_name)

        return re.compile(driver(self.name, self.fields), re.IGNORECASE)

    def __format__(self, spec):
        opts = dict(map(lambda s: re.split(r'=|\Z', s, maxsplit=1), spec.split(':')))
        pat = group(
            '(?:{sep}?(?:{pat}))+'.format(sep=opts['x'] or r'[-./]', pat=self.compile(1).pattern),
            name=self.name
        ) if 'x' in opts else self.compile().pattern
        return r'(?i:{})'.format(pat) if '-i' not in opts else pat

    @classmethod
    def load_vocab(cls, name, **kwargs):
        return cls(
            name, json.load(pkg_resources.resource_stream(__name__, f'vocabs/{name.lower()}.json')), **kwargs
        )


# Provides extra detail about the malware, including how it is used as part of a multicomponent
# threat. In the example above,
LABELS = VocabRegex.load_vocab('LABELS')
LANGS = VocabRegex.load_vocab('LANGS')
ARCHIVES = VocabRegex.load_vocab('ARCHIVES')
MACROS = VocabRegex.load_vocab('MACROS')
OSES = VocabRegex.load_vocab('OPERATING_SYSTEMS')
HEURISTICS = VocabRegex.load_vocab('HEURISTICS')
OBFUSCATIONS = VocabRegex.load_vocab('OBFUSCATIONS')

PLATFORM = group(OSES, ARCHIVES, MACROS, LANGS)

IDENT = r"""(?P<NAME> (?P<FAMILY>CVE-[\d-]+|[A-Z0-9_a-z-]+)
                ([.]?(?<=[.])(?P<VARIANT>[a-zA-Z0-9]*([.]\d+\Z)?))?
                (!(?P<SUFFIX>\w+))?)"""
