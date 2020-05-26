from functools import lru_cache
import json
import regex as re
from typing import Dict, Mapping, Union

from pkg_resources import resource_stream

from polyunite.utils import group

class VocabRegex:
    name: 'str'
    fields: 'Dict[str, Union[Dict, str]]'

    def __init__(self, name, fields):
        self.name = name
        self.fields = fields

    @lru_cache(typed=True)
    def compile(self, start: 'int' = 0, end: 'int' = 1):
        """Compile regex, name groups for fields nested at least ``start`` and at most ``end`` deep"""
        def driver(name, entries, depth=0):
            group_name = start <= depth <= end and name.isidentifier() and name
            if isinstance(entries, Mapping):
                aliases = entries.get('__alias__', ())
                children = (driver(k, v, depth + 1) for k, v in entries.items() if not k.startswith('__'))
                return group(self.name != name and name, *aliases, *children, name=group_name)
            else:
                return group(name, name=group_name)

        return re.compile(driver(self.name, self.fields), re.IGNORECASE)

    def __format__(self, spec):
        """controls how this class should be formatted (also provides __str_)"""
        return '(?i:{})'.format(self.compile().pattern)

    @classmethod
    def from_resource(cls, name: 'str'):
        return cls(name, json.load(resource_stream(__name__, f'vocabs/{name.lower()}.json')))
