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


# THIS class is a temporary hack to get polyscore going.
# Do not invest (much) work into improving beyond bugfixes
class VocabRegex(string.Formatter):
    name: str
    fields: Dict[str, Union[Dict, str]]
    _tok_regex: str

    def __init__(self, name, fields):
        self.name = name
        self.fields = fields
        self._tok_regex = None

    def find(self, value={}, *, backup=iter(())) -> Optional[str]:
        "Attempt to extract & normalize a group with the same name as this ``VocabRegex``"
        needle = value.get(self.name) if type(value) == dict else value
        yield from filter(None, re.finditer(self.token_regex(), needle or r'\Z\A', re.IGNORECASE))

    def visitor(self, kv, *, path=()) -> Iterator[Tuple[str, List[str]]]:
        yield from ((alias, path) for alias in kv.get('__alias__', ()))
        for npath, k, v in ((path + (k, ), k, v) for k, v in kv.items() if not k.startswith('__')):
            yield (k, npath)
            if isinstance(v, Mapping):
                yield from self.visitor(v, path=npath)

    def __str__(self):
        fields = '|'.join({str(kv[0]) for kv in self.visitor(self.fields)})
        return fr'(?i:(?P<{self.name}>{fields}))'

    def token_regex(self, rebuild=False):
        if not self._tok_regex or rebuild:
            gs = {}
            for (key, (name, *_)) in self.visitor(self.fields):
                gs.setdefault(name, set()).add(key)
            self._tok_regex = '|'.join(fr'(?P<{g}>{"|".join(rx)})' for g, rx in gs.items())
        return self._tok_regex

    @classmethod
    def load_vocab(cls, name):
        return cls(name.upper(), json.load(pkg_resources.resource_stream(__name__, f'vocabs/{name}.json')))


# Provides extra detail about the malware, including how it is used as part of a multicomponent
# threat. In the example above,
LABELS = VocabRegex.load_vocab('labels')
LANGS = VocabRegex.load_vocab('langs')
ARCHIVES = VocabRegex.load_vocab('archives')
MACROS = VocabRegex.load_vocab('macros')
OSES = VocabRegex.load_vocab('operating_systems')
HEURISTICS = VocabRegex.load_vocab('heuristics')
OBFUSCATIONS = VocabRegex.load_vocab('obfuscations')

PLATFORM = rf"{OSES}|{ARCHIVES}|{MACROS}|{LANGS}"

BEHAVIORS = r"(?P<BEHAVIOR>AntiVM)"

IDENT = r"(?P<NAME>((?P<FAMILY>(((CVE-[\d-]+)|[-\w]+?)(\.\w+(?=(\.\d+)))?))" + \
        r"((?P<VARIANTSEP>\.)(?P<VARIANT>\w*))?" + \
        r"((?P<SUFFIXSEP>!)(?P<SUFFIX>\w*))?))"

EXPLOITS = r'(?P<EXPLOIT>(Exploit|Exp))'
