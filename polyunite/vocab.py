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
        return re.compile(self.pattern(start, end), re.IGNORECASE | re.BESTMATCH)

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

CVE_PATTERN = r'(?:(?P<CVE>(?|CVE|Cve|cve)[-_]?(?P<CVEYEAR>[[:digit:]]{4})[-_]?(?P<CVENTH>[[:digit:]]+))[A-Za-z]*)'


def VARIANT_ID(*extra):
    return group(
        r'(?i:\L<suffixes>)',
        *extra,
        r'[#]\d+',
        r'[!]ET',
        r'[.][[:alpha:]]+[!][[:digit:]]+',
        r'[.][[:digit:]]+[!][[:alpha:]]+',
        r'[!][A-Z]+[.][0-9]+',
        r'[.](?:GEN|Gen|gen)\d*',
        r'[.!@#](?-i:[A-Z]+|[a-z]+|[A-F0-9]+|[a-f0-9]+)',
        r'[.](?-i:[A-Z]{,3}|[a-z]{,3}|[0-9]{,3})',
        r'[.][[:alnum:]]',
        name='VARIANT'
    )


def FAMILY_ID(*extra):
    return '(?P<FAMILY>{}|(?!CVE){})'.format(
        CVE_PATTERN,
        group(
            *extra,
            r'MS[[:digit:]]{2}-[[:digit:]]+',
            r'(?:[a-z]?[A-Z][A-Za-z]{2,}){i<=3:[-\d]}',
            r'(?P<nonmalware>(?i:eicar(?>.?test(?>.?file)?)?([.]com)?))',
        ),
    )


def IDENT(extra_families=[], extra_variants=[]):
    """Build a family & variant subpattern"""
    return rf'(?P<NAME>{FAMILY_ID(*extra_families)}?({VARIANT_ID(*extra_variants)}{{,2}}?)?)'
