from functools import lru_cache
import json
from typing import List, Mapping, Optional

from pkg_resources import resource_stream
import regex as re


def group(*choices, fmt='(?:{})', name: 'Optional[str]' = None):
    """Group a regular expression"""
    spec = '(?P<%s>{})' % name if name else fmt
    return spec.format('|'.join(set(map(format, filter(None, choices)))))


class VocabRegex:
    name: 'str'
    depth: 'int'
    children: 'List[VocabRegex]'
    aliases: 'List[str]'

    def __init__(self, name, fields, *, depth=0):
        values = [(f, fields[f]) for f in fields if not f.startswith('__')]
        self.name = name
        self.depth = depth
        self.aliases = list(fields.get('__alias__', ()))
        self.aliases.extend(name for name, val in values if isinstance(val, str))
        self.children = [
            VocabRegex(name, val, depth=depth + 1) for name, val in values if isinstance(val, Mapping)
        ]
        if depth > 0:
            self.aliases.append(name)

    @lru_cache(typed=True)
    def compile(self, start: 'int' = 0, end: 'int' = 1) -> 're.Pattern':
        """Compile regex, name groups for fields nested at least ``start`` and at most ``end`` deep"""
        return re.compile(self.pattern(start, end), re.IGNORECASE)

    def pattern(self, start: 'int' = 0, end: 'int' = 1) -> 'str':
        """Convert this grouped regular expression pattern"""
        use_group_name = start <= self.depth <= end and self.name.isidentifier()
        return group(
            *(c.pattern() for c in self.children),
            *self.aliases,
            name=self.name if use_group_name else None,
        )

    @property
    def sublabels(self):
        return list(v.name for v in self.iter() if v.depth > self.depth)

    def iter(self):
        yield self
        for c in self.children:
            yield from c.iter()

    def __format__(self, spec):
        """controls how this class should be formatted (also provides __str_)"""
        return '(?i:{})'.format(self.pattern())

    @classmethod
    def from_resource(cls, name: 'str'):
        return cls(name, json.load(resource_stream(__name__, f'vocabs/{name.lower()}.json')))
