from functools import lru_cache
import json
from typing import Iterator, List, Mapping, Optional

from pkg_resources import resource_stream
import regex as re

from polyunite.utils import group, antecedent


class VocabRegex:
    name: 'str'
    parent: 'Optional[VocabRegex]'
    children: 'List[VocabRegex]'
    aliases: 'List[str]'

    def __init__(self, name, fields, *, parent=None):
        values = [(n, v) for n, v in fields.items() if not n.startswith('__')]
        self.name = name
        self.parent = parent
        self.children = [VocabRegex(n, v, parent=self) for n, v in values if isinstance(v, Mapping)]
        self.aliases = fields.get('__alias__', []) + [n for n, v in values if isinstance(v, str)]
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
        return (v.name for v in self.iter() if v.depth > self.depth and v.name)

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

def IDENT(extra_families=[], extra_variants=[]):
    """Build a family & variant subpattern"""
    return r'(?P<NAME>\b{family}?\b{variant}{{,2}})'.format(
        family=group(
            r'(?P<nonmalware>(?i:eicar(?:[^a-z]test(?:[^a-z]file)?)?([.]com)?))',
            r'(?P<CVE>CVE-?\d{4}-?\d+){i<=1:[A-Za-z]}',
            r'[A-Za-z]{2,3}(?!$)',
            r'i?(?:[A-Z][A-Za-z]{2,}){i<=3:\d}',
            *extra_families,
            name='FAMILY',
        ),
        variant=group(
            rf'{antecedent:[.!@#]}(?-i:[A-Z]+|[a-z]+|[A-F0-9]+|[a-f0-9]+)',
            rf'(?i:{antecedent:[.!@#-]}\L<suffixes>)',
            rf'([!]@mm|@m)',
            rf'{antecedent:[.]}[A-Z0-9]+',
            *extra_variants,
            name='VARIANT'
        )
    )
