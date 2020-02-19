import json
from typing import Dict, Mapping, Union

import pkg_resources

from polyunite.utils import trx


def load_vocab(name):
    return json.load(pkg_resources.resource_stream(__name__, f'vocabs/{name}.json'))


class VocabRegex:
    name: str
    fields: Dict[str, Union[Dict, str]]

    def __str__(self):
        return self.build()

    def __init__(self, name, fields):
        self.name = name
        self.fields = fields

    def build(self, **kwargs):
        return '(?P<{name}>{fields})'.format(
            name=kwargs.get('name', self.name),
            fields='|'.join([k for k, _ in self.visitor(self.fields, exclude=kwargs.get('exclude', []))])
        )

    @classmethod
    def combine(cls, name, *vocabs, **kwargs):
        return '(?P<{name}>({fields}))'.format(
            name=name, fields='|'.join([v.build(exclude=kwargs.get('exclude', [])) for v in vocabs])
        )

    def find(self, groups):
        value = groups.get(self.name)
        needle = trx(value)
        if not value or not needle:
            return needle
        for k, path in self.visitor(self.fields):
            if trx(k) == needle:
                return path[0]
        return None  # f'(NOTFOUND)[{needle}]'

    def visitor(self, kv, exclude=[], path=[]):
        for k in kv:
            if k == '__alias__':
                for alias in kv[k]:
                    yield (alias, path)
            elif k.startswith('__'):
                continue
            elif k not in exclude:
                yield (k, path + [k])
            if isinstance(kv[k], Mapping):
                yield from self.visitor(kv[k], exclude=exclude, path=path + [k])


heuristics = ['heur[a-z]*', 'gen(eric)?' 'agent']

# Provides extra detail about the malware, including how it is used as part of a multicomponent
# threat. In the example above,
SUFFIXES = VocabRegex('SUFFIX', load_vocab('suffixes'))
EXPLOITS = VocabRegex('EXPLOIT', {'Exploit': {'__desc__': '', '__alias__': ['Exp']}})
LABELS = VocabRegex('LABEL', load_vocab('labels'))
LANGS = VocabRegex('LANGS', load_vocab('langs'))
ARCHIVES = VocabRegex('ARCHIVES', load_vocab('archives'))
MACROS = VocabRegex('MACROS', load_vocab('macros'))
OSES = VocabRegex('OPERATINGSYSTEM', load_vocab('operating_systems'))
PLATFORM_REGEXES = VocabRegex.combine('PLATFORM', ARCHIVES, MACROS, OSES, LANGS)
