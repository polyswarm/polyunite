from typing import Iterator, List, Optional

from functools import lru_cache
import json
from pkg_resources import resource_stream
import regex as re

from ..utils import group


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
            self.match = [{'const': v} if isinstance(v, str) else v for v in fields.get('match', [])]
            self.tags = {f.lower() for f in fields.get('tags', [])}
            self.description = fields.get('description', None)
            self.children = [VocabRegex(n, v, parent=self) for n, v in fields.get('children', dict()).items()]
        else:
            raise ValueError(name, fields)

    @property
    def aliases(self):
        """All identifying case-insensitive strings"""
        return map(re.escape, filter(None, (m.get('const') for m in self.match)))

    @property
    def patterns(self):
        """All identifying regular expressions"""
        return filter(None, (m.get('pattern') for m in self.match))

    @lru_cache(typed=True)
    def compile(self, start: 'int' = 0, end: 'int' = 1) -> 're.Pattern':
        """Compile regex, name groups for fields nested at least ``start`` and at most ``end`` deep"""
        return re.compile(self.pattern(start, end), re.IGNORECASE)

    def pattern(self, start: 'int' = 0, end: 'int' = 1) -> 'str':
        """Convert this grouped regular expression pattern"""
        use_group_name = start <= self.depth <= end
        name = self.group_name if use_group_name else None
        if any(self.match) or any(self.children):
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
        return (v.name for v in self.iter() if v.depth > self.depth and v.name)

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
        return cls(name, json.load(resource_stream(__name__, '%s.json' % name.lower())))

    def iteraliases(self):
        for v in self.iter():
            yield from v.aliases
