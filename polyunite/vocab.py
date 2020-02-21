import json
import re
from typing import Dict, Iterator, List, Mapping, Optional, Tuple, Union

import pkg_resources

from polyunite.utils import trx


def load_vocab(name):
    # these identifiers are sourced from https://maecproject.github.io/documentation/maec5-docs/#introduction
    return json.load(pkg_resources.resource_stream(__name__, f'vocabs/{name}.json'))


class VocabRegex:
    name: str
    fields: Dict[str, Union[Dict, str]]

    def __str__(self):
        return self.build()

    def __init__(self, name, fields):
        self.name = name
        self.fields = fields

    def build(self, **kwargs) -> str:
        return '(?P<{name}>{fields})'.format(
            name=kwargs.get('name', self.name),
            fields='|'.join([k for k, _ in self.visitor(self.fields, exclude=kwargs.get('exclude', []))])
        )

    def combine(self, name, *vocabs, **kwargs) -> str:
        return '(?P<{name}>({fields}))'.format(
            name=name,
            fields='|'.join([v.build(exclude=kwargs.get('exclude', [])) for v in [self] + list(vocabs)])
        )

    def find(self, groups=None, value=None, every=False) -> Optional[str]:
        "Attempt to extract & normalize a group with the same name as this ``VocabRegex``"
        needle = value or groups.get(self.name)
        results = set()
        if needle:
            for k, (category, *_) in self.visitor(self.fields):
                if re.fullmatch(k, needle, re.IGNORECASE):
                    if not every:
                        return category
                    if category not in results:
                        results.add(category)
        return list(results)

    def visitor(self, kv, exclude=[], path=[]) -> Iterator[Tuple[str, List[str]]]:
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


# Provides extra detail about the malware, including how it is used as part of a multicomponent
# threat. In the example above,
SUFFIXES = VocabRegex('SUFFIX', load_vocab('suffixes'))
EXPLOITS = VocabRegex('EXPLOIT', {'Exploit': {'__desc__': '', '__alias__': ['Exp']}})
LABELS = VocabRegex('LABEL', load_vocab('labels'))
LANGS = VocabRegex('LANGS', load_vocab('langs'))
ARCHIVES = VocabRegex('ARCHIVES', load_vocab('archives'))
MACROS = VocabRegex('MACROS', load_vocab('macros'))
OSES = VocabRegex('OPERATINGSYSTEM', load_vocab('operating_systems'))
HEURISTICS = VocabRegex('HEURISTICS', load_vocab('heuristics'))
PLATFORM_REGEXES = OSES.combine('PLATFORM', ARCHIVES, MACROS, LANGS)
