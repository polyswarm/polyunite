from functools import lru_cache
from itertools import chain
import json
import re
from typing import Any, Dict, Mapping, Union

from pkg_resources import resource_stream


def group(*choices, fmt='(?:{})', name=None):
    spec = '(?P<%s>{})' % name if name else fmt
    return spec.format('|'.join(set(map(format, filter(None, choices)))))


class VocabRegex:
    name: 'str'
    fields: 'Dict[str, Union[Dict, str]]'

    def __init__(self, name, fields):
        self.name = name
        self.fields = fields

    @lru_cache
    def compile(self, start=0, end=1):
        """Compile regex, name groups for fields nested at least ``start`` and at most ``end`` deep"""
        def driver(name, entries, depth=0):
            group_name = start <= depth <= end and name.isidentifier() and name
            return group(
                self.name != name and name,
                *entries.get('__alias__', ()),
                *(driver(k, v, depth + 1) for k, v in entries.items() if not k.startswith('__')),
                name=group_name
            ) if isinstance(entries, Mapping) else group(name, name=group_name)

        return re.compile(driver(self.name, self.fields), re.IGNORECASE)

    def __format__(self, spec):
        """controls how this class should be formatted (also provides __str_)

        formatters:
          x=str: controls if this regex should allow multiple submatches
          {start,end}=int: controls the 'start' or 'end' compile parameters
        """
        fmt = '(?i:{})'
        opts = dict(map(re.compile('=|$').split, spec.split(':')))
        cargs = {k: int(opts[k]) for k in ('start', 'end') if k in opts}
        if 'x' in opts:
            cargs.update({'start': cargs.get('end', 1), 'end': cargs.get('end', 2)})
            # controls how to separate different sub-sections, by default will use [-./] or \b
            delim = opts["x"] or "[-./]?"
            fmt = fr'(?P<{self.name}>(?:{delim}{fmt})+)'
        return fmt.format(self.compile(**cargs).pattern)

    @classmethod
    def load_vocab(cls, name):
        return cls(name, json.load(resource_stream(__name__, f'vocabs/{name.lower()}.json')))


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

IDENT = r"""(?P<NAME> (?P<FAMILY>(?:CVE-[\d-]+)|(?:[\w_-]+))
                ([.]?(?<=[.])(?P<VARIANT>(?:[a-zA-Z0-9]*)([.]\d+\Z)?))?
                (!(?P<SUFFIX>\w+))?)"""
