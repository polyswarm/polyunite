from typing import Iterator, List, Optional

from functools import lru_cache
import json
from pkg_resources import resource_stream
import regex as re

from polyunite.utils import antecedent, group


class VocabRegex:
    name: 'str'
    parent: 'Optional[VocabRegex]'
    children: 'List[VocabRegex]'
    description: 'Optional[str]'
    aliases: 'List[str]'

    def __init__(self, name, fields, *, parent=None):
        self.name = name
        self.parent = parent

        if isinstance(fields, dict):
            self.aliases = fields.pop('__alias__', [])
            self.description = fields.pop('__desc__', None)
            # self.aliases.extend([n for n, v in values if isinstance(v, str)])
            self.children = [
                VocabRegex(n, v, parent=self) for n, v in fields.items() if not n.startswith('__')
            ]
        elif isinstance(fields, str):
            self.children = []
            self.aliases = []
            self.description = fields
        else:
            raise ValueError(name, fields)

        if parent:
            self.aliases.append(name)

    @lru_cache(typed=True)
    def compile(self, start: 'int' = 0, end: 'int' = 1) -> 're.Pattern':
        """Compile regex, name groups for fields nested at least ``start`` and at most ``end`` deep"""
        return re.compile(self.pattern(start, end), re.IGNORECASE)

    def pattern(self, start: 'int' = 0, end: 'int' = 1) -> 'str':
        """Convert this grouped regular expression pattern"""
        use_group_name = start <= self.depth <= end and self.name.isidentifier()
        name = self.name if use_group_name else None
        return group(*(c.pattern(start, end) for c in self.children), *self.aliases, name=name)

    def iter(self) -> 'Iterator[VocabRegex]':
        yield self
        for c in self.children:
            yield from c.iter()

    @property
    def depth(self) -> 'int':
        return (1 + self.parent.depth) if self.parent else 0

    @property
    def sublabels(self) -> 'Iterator[str]':
        yield from (v.name for v in self.iter() if v.depth > self.depth and v.name)

    @property
    def entries(self) -> 'Iterator[str]':
        for v in self.iter():
            yield from v.aliases

    def __format__(self, spec) -> 'str':
        return '(?i:{})'.format(self.pattern())

    @classmethod
    def from_resource(cls, name: 'str') -> 'VocabRegex':
        return cls(name, json.load(resource_stream(__name__, 'vocabs/%s.json' % name.lower())))


# regular expressions which match 'vocabularies' of classification components
LABELS = VocabRegex.from_resource('LABELS')
LANGS = VocabRegex.from_resource('LANGS')
ARCHIVES = VocabRegex.from_resource('ARCHIVES')
MACROS = VocabRegex.from_resource('MACROS')
OSES = VocabRegex.from_resource('OPERATING_SYSTEMS')
HEURISTICS = VocabRegex.from_resource('HEURISTICS')
OBFUSCATIONS = VocabRegex.from_resource('OBFUSCATIONS')
SUFFIXES = VocabRegex.from_resource('SUFFIXES')
PLATFORM = group(OSES, ARCHIVES, MACROS, LANGS, HEURISTICS)

CVE_PATTERN = r'(?P<CVE>((?:CVE|cve)[-_]?(?P<CVEYEAR>\d{4})[-_]?(?P<CVENTH>\d*))[A-Za-z]*)'


def IDENT(extra_families=[], extra_variants=[]):
    """Build a family & variant subpattern"""
    return r'(?P<NAME>{family}?({variant}{{,2}}?)?)'.format(
        family=group(
            CVE_PATTERN,
            *extra_families,
            r'([A-Za-z]{2,3}(?!$))',
            r'(i?(?:[A-Z][A-Za-z]{2,}){i<=3:\d})',
            r'(?P<nonmalware>(?i:eicar(?>.?test(?>.?file)?)?([.]com)?))',
            name='FAMILY',
        ),
        variant=group(
            *extra_variants,
            rf'((?i:{antecedent:[.!@#-]}\L<suffixes>))',
            rf'({antecedent:[.!@#]}(?-i:[A-Z]+|[a-z]+|[A-F0-9]+|[a-f0-9]+))',
            r'([!](@mm|@m))',
            rf'({antecedent:[.]}[A-Z0-9]+)',
            name='VARIANT'
        )
    )
