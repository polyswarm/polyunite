import json
import re
import string
from typing import (
    Dict,
    Iterable,
    Iterator,
    List,
    Mapping,
    Optional,
    Tuple,
    Union,
)

import pkg_resources

from polyunite.utils import trx


def load_vocab(name):
    # these identifiers are sourced from https://maecproject.github.io/documentation/maec5-docs/#introduction
    return json.load(pkg_resources.resource_stream(__name__, f'vocabs/{name}.json'))


class VocabRegex(string.Formatter):
    name: str
    fields: Dict[str, Union[Dict, str]]

    def __str__(self):
        return self.build()

    def __init__(self, name, fields):
        self.name = name
        self.fields = fields

    def named_group(
        self, name: str = None, fields: Iterable[str] = [], include: Iterable = [], exclude: Iterable = []
    ):
        fs = set(map(str, (*fields, *include))).difference(map(str, exclude))
        return '(?i:(?P<{name}>{fields}))'.format(name=name or self.name, fields='|'.join(fs))

    def build(self, **kwargs) -> str:
        return self.named_group(
            name=kwargs.get('name', self.name), fields=[k for k, _ in self.visitor(self.fields)], **kwargs
        )

    def combine(self, name, *vocabs, **kwargs) -> str:
        return self.named_group(name=name, fields=[self, *vocabs], **kwargs)

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
LABELS = VocabRegex('LABEL', load_vocab('labels'))
LANGS = VocabRegex('LANGS', load_vocab('langs'))
ARCHIVES = VocabRegex('ARCHIVES', load_vocab('archives'))
MACROS = VocabRegex('MACROS', load_vocab('macros'))
OSES = VocabRegex('OPERATINGSYSTEM', load_vocab('operating_systems'))
HEURISTICS = VocabRegex('HEURISTIC', load_vocab('heuristics'))

PLATFORM = OSES.combine('PLATFORM', ARCHIVES, MACROS, LANGS)
OBFUSCATIONS = VocabRegex('OBFUSCATION', load_vocab('obfuscation_methods'))

BEHAVIORS = r"(?P<BEHAVIOR>AntiVM)"

IDENT = r"(?P<NAME>((?P<FAMILY>(((CVE-[\d-]+)|[-\w]+?)(\.\w+(?=(\.\d+)))?))" + \
        r"((?P<VARIANTSEP>\.)(?P<VARIANT>\w*))?" + \
        r"((?P<SUFFIXSEP>!)(?P<SUFFIX>\w*))?))"

EXPLOITS = r'(?P<EXPLOIT>(Exploit|Exp))'
