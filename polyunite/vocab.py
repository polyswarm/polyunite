from typing import Iterator, List, Optional

from functools import lru_cache
import json
from pkg_resources import resource_stream
import regex as re

from polyunite.utils import group


class VocabRegex:
    name: 'str'
    parent: 'Optional[VocabRegex]'
    children: 'List[VocabRegex]'
    description: 'Optional[str]'
    aliases: 'List[str]'

    def __init__(self, name, fields, *, parent=None):
        self.name = name
        self.parent = parent
        self.group_name = name

        if isinstance(fields, dict):
            match = [{'const': v} if isinstance(v, str) else v for v in fields.get('match', [])]
            self.aliases = [re.escape(v['const']) for v in match if 'const' in v]
            self.patterns = [v['pattern'] for v in match if 'pattern' in v]
            self.tags = {f.lower() for f in fields.get('tags', [])}
            self.description = fields.get('description', None)
            self.children = [VocabRegex(n, v, parent=self) for n, v in fields.get('children', dict()).items()]
        else:
            raise ValueError(name, fields)

    @lru_cache(typed=True)
    def compile(self, start: 'int' = 0, end: 'int' = 1) -> 're.Pattern':
        """Compile regex, name groups for fields nested at least ``start`` and at most ``end`` deep"""
        return re.compile(self.pattern(start, end), re.IGNORECASE)

    def pattern(self, start: 'int' = 0, end: 'int' = 1) -> 'str':
        """Convert this grouped regular expression pattern"""
        use_group_name = start <= self.depth <= end
        name = self.group_name if use_group_name else None
        return group(
            *(c.pattern(start, end) for c in self.children),
            *self.aliases,
            *self.patterns,
            name=name,
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

    def __format__(self, spec) -> 'str':
        """Format this vocabulary as a regular expression, accepts `-g` to remove groups and `-i` for case-sensitivity"""
        pat = self.pattern(start=1, end=0) if spec and '-g' in spec else self.pattern()
        return pat if spec and '-i' in spec else '(?i:{})'.format(pat)

    def __str__(self):
        return format(self)

    def __getitem__(self, k):
        """Find a child vocabulary by name"""
        try:
            return next(c for c in self.children if c.name == k)
        except StopIteration:
            raise KeyError

    def has_tag(self, tag):
        """Check if this vocabulary has an associated tag"""
        return tag.lower() in self.tags

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

CVE_PATTERN = r'(?P<CVE>(CVE|Cve|cve)([-_]?(?P<CVEYEAR>[0-9]{4})([-_]?((?P<CVENTH>[0-9]+)[[:alpha:]]*))))'


def VARIANT_ID(*extra):
    return group(
        format(SUFFIXES, '-g:-i'),
        *extra,
        r'[.][A-Z]{,3}',
        r'[.][a-z0-9]{,8}',
        r'[.][A-Z][a-z]{2}',
        name='VARIANT'
    )


def FAMILY_ID(*extra):
    return '(?P<FAMILY>{}|{}|{})'.format(
        CVE_PATTERN,
        r'MS[0-9]{2}-[0-9]{,6}',
        group(
            *extra,
            format(HEURISTICS['family'], '-g'),
            format(OBFUSCATIONS, '-g'),
            r'CVE(-[0-9]{4})?(?![0-9.-_])',
            r'[0-9a-z]{1,2}[A-Z][a-zA-Z]{2,}',
            r'[A-Z][a-zA-Z0-9_]{3,}',
        ),
    )


def IDENT(extra_families=[], extra_variants=[]):
    """Build a family & variant subpattern"""
    return rf'(?P<VEID>{FAMILY_ID(*extra_families)}?({VARIANT_ID(*extra_variants)}{{,2}}?)?)'
