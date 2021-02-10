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
            self.match = [{'const': v} if isinstance(v, str) else v for v in fields.get('match', [])]
            self.aliases = [v['const'] for v in self.match if 'const' in v]
            self.patterns = [v['pattern'] for v in self.match if 'pattern' in v]
            self.description = fields.get('description', None)
            # self.aliases.extend([n for n, v in values if isinstance(v, str)])
            self.children = [VocabRegex(n, v, parent=self) for n, v in fields.get('children', dict()).items()]
        else:
            raise ValueError(name, fields)

    @lru_cache(typed=True)
    def compile(self, start: 'int' = 0, end: 'int' = 1) -> 're.Pattern':
        """Compile regex, name groups for fields nested at least ``start`` and at most ``end`` deep"""
        return re.compile(self.pattern(start, end), re.IGNORECASE)

    def pattern(self, start: 'int' = 0, end: 'int' = 1) -> 'str':
        """Convert this grouped regular expression pattern"""
        use_group_name = start <= self.depth <= end and self.name.isidentifier()
        name = self.name if use_group_name else None
        return group(
            *(c.pattern(start, end) for c in self.children), *self.aliases, *self.patterns, name=name
        )

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
PLATFORM = group(OSES, ARCHIVES, MACROS, LANGS, HEURISTICS, OBFUSCATIONS)

CVE_PATTERN = r'(?P<CVE>(?i:CVE)(?:[-_]?(?P<CVEYEAR>[0-9]{4})(?:[-_]?(?:(?P<CVENTH>[0-9]+)[[:alpha:]]*))))'


def VARIANT_ID(*extra):
    return group(
        r'(?i:\L<suffixes>)',
        *extra,
        r'[#]\d+',
        r'[!]ET',
        r'[.!@#][[:xdigit:]]+',
        r'[.][a-z]{3,8}',
        r'[.](?-i:[A-Z]{,3}|[a-z]{,3}|[0-9]{,3})',
        r'[.](?|GEN|Gen|gen)[0-9]+',
        r'[!][[:alnum:]]',
        r'[.][[:alnum:]]',
        r'[.][A-Z][a-z]{2}',
        name='VARIANT'
    )


def FAMILY_ID(*extra, heuristics=True):
    if heuristics:
        extra = *extra, str(HEURISTICS)

    return '(?P<FAMILY>{}|MS[0-9]{{2}}-[0-9]{{,6}}|{})'.format(
        CVE_PATTERN,
        group(
            *extra,
            str(next(c for c in HEURISTICS.children if c.name == 'family')),
            str(OBFUSCATIONS),
            r'CVE(?:-[0-9]{4})?',
            r'[0-9a-z]{1,2}[A-Z][a-zA-Z]{2,}',
            r'[A-Z][a-zA-Z0-9_]{3,}',
        ),
    )


def IDENT(extra_families=[], extra_variants=[]):
    """Build a family & variant subpattern"""
    return rf'(?P<VEID>{FAMILY_ID(*extra_families)}?({VARIANT_ID(*extra_variants)}{{,2}}?)?)'
