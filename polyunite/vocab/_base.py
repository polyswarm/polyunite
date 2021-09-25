from typing import Iterator, List, Optional

from functools import lru_cache
import json
import os.path
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
            self.aliases = list(map(re.escape, filter(None, fields.get('match-exact', []))))
            self.patterns = list(filter(None, fields.get('match-regex', [])))
            self.tags = fields.get('tags', dict())
            self.description = fields.get('description', None)
            self.children = [
                VocabRegex(n, v, parent=self) for n, v in fields.get('children', dict()).items()
            ]
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
        if self.aliases or self.patterns or self.children:
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
        return tag in self.tags

    @classmethod
    def from_resource(cls, name: 'str') -> 'VocabRegex':
        with open(os.path.join(os.path.dirname(__file__), '%s.json' % name.lower()), 'rt') as f:
            return cls(name, json.load(f))

    def iteraliases(self):
        for v in self.iter():
            yield from v.aliases
