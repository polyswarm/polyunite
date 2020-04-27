import collections
from functools import partial
from itertools import chain
import re
from typing import ClassVar, Dict, Optional
import operator

from polyunite.utils import GROUP_COLORS, reset
from polyunite.registry import registry
from polyunite.colors import GROUP_COLORS, RESET
from polyunite.vocab import ARCHIVES, HEURISTICS, IDENT, LABELS, LANGS, MACROS, OBFUSCATIONS, OSES, PLATFORM
from polyunite.errors import ClassificationDecodeError


def extract_vocabulary(vocab):
    find_iter = vocab.compile(1, 1).finditer
    _last_group = operator.attrgetter('lastgroup')
    name = vocab.name

    def driver(self, recieve=lambda m: next(m, None)):
        field = self.get(name)
        if isinstance(field, str):
            return recieve(filter(None, (s.lastgroup for s in find_iter(field))))
        else:
            return recieve(iter(()))

    return driver


class ClassificationDecoder(collections.UserDict):
    pattern: 'ClassVar[str]'
    regex: 'ClassVar[re.Pattern]'

    operating_system = property(extract_vocabulary(OSES))
    language = property(extract_vocabulary(LANGS))
    macro = property(extract_vocabulary(MACROS))
    labels = property(extract_vocabulary(LABELS, recieve=set))

    @property
    def name(self) -> str:
        return self.get('FAMILY') or self.source

    @property
    def source(self):
        return self.match.string

    @property
    def av_vendor(self):
        return self.__class__.__name__

    @property
    def is_heuristic(self) -> Optional[bool]:
        match = HEURISTICS.compile(1, 1).fullmatch
        for vocab in ('HEURISTICS', 'FAMILY', 'LABELS', 'VARIANT'):
            field = self.get(vocab)
            if isinstance(field, str) and match(field):
                return True
        return False

    @classmethod
    def __init_subclass__(cls):
        if not isinstance(cls.pattern, re.Pattern):
            cls.regex = re.compile(cls.pattern, re.VERBOSE)
        registry.map_to_decoder(cls.__name__, cls)

    def __init__(self, classification: str):
        match = self.regex.fullmatch(classification)
        if not match:
            raise ClassificationDecodeError
        self.match = match
        self.data = {k: v for k, v in match.groupdict().items() if v}

    def colorize(self) -> str:
        """Colorize a classification string"""
        ss = self.source
        # interleave the color, match & reset between the part before & after the match (from rpartition)
        for name, match in filter(lambda kv: kv[0] in GROUP_COLORS, self.items()):
            ss = ''.join(chain(*zip(ss.rpartition(match), (GROUP_COLORS[name], RESET, ''))))
        return ss

class Alibaba(ClassificationDecoder):
    pattern = rf"^(?:(?:{OBFUSCATIONS}|{LABELS:x}):)?(?:({PLATFORM})\/)?(?:{IDENT})$"


class ClamAV(ClassificationDecoder):
    pattern = rf"""^
        (?:(?P<PREFIX>BC|Clamav))?
        (?:(\.|^)(?:{PLATFORM}|{LABELS}|{OBFUSCATIONS}))*?

        (?:(\.|^)(?P<FAMILY>\w+)(?:(\:\w|\/\w+))*(?:-(?P<VARIANT>[\-0-9]+)))?$"""


class DrWeb(ClassificationDecoder):
    pattern = rf"""^
    ((?i:{HEURISTICS})(\s+(of\s*)?)?)?
              (?:(\.|\A|\b){PLATFORM})?
              (?:(\.|\A|\b){LABELS})?
              (?:(\.|\b)( # MulDrop6.38732 can appear alone or in front of another `.`
                  (?P<FAMILY>[A-Za-z][-\w\.]+?)
                  (?:\.|\Z) # and either end or continue with `.`
                  (?P<VARIANT>[0-9]+)?
                  (?:[.]?(?P<SUFFIX>(origin|based)))?))?$"""


class Ikarus(ClassificationDecoder):
    pattern = rf"""
        ^({OBFUSCATIONS}\.)?
              (?:{HEURISTICS}\:?)?
              (?:(?:\A|\.|\b)({LABELS:x}|{PLATFORM}))*?
              (?:[.]?{IDENT})?$"""


class Jiangmin(ClassificationDecoder):
    pattern = rf"""^(?:{HEURISTICS}:?)?
              (?:(?:{LABELS:x}|{OBFUSCATIONS}|{PLATFORM})[./]|\b)+?
              {IDENT}?(?:[.](?P<GENERATION>[a-z]))?$"""


class K7(ClassificationDecoder):
    pattern = rf"^{LABELS:x}? (?:\s*\(\s* (?P<VARIANT>[a-f0-9]+) \s*\))?$"


class Lionic(ClassificationDecoder):
    pattern = rf"^{LABELS}?(?:(^|\.)(?:{PLATFORM}))?(?:(?:\.|^){IDENT})?$"


class NanoAV(ClassificationDecoder):
    pattern = rf"""^
        {LABELS:x}?
              (?:[.]?(?P<NANO_TYPE>(Text|Url)))?
              (?:(\b|[.]){PLATFORM})*?
              (?:[.]?{IDENT})$"""


class Qihoo360(ClassificationDecoder):
    pattern = rf"""
        ^(?:{HEURISTICS}(?:/|(?:(?<=VirusOrg)\.)))?
              (?:
                  (?:Application|{MACROS}|{LANGS}|{OSES}|{ARCHIVES}|{LABELS:x}|(QVM\d*(\.\d)?(\.[0-9A-F]+)?))
              [./])*
              {IDENT}?$"""


class QuickHeal(ClassificationDecoder):
    pattern = rf"""
        ^(?:{HEURISTICS}\.)?
              # This trailing (\)$) handle wierd cases like 'Adware)' or 'PUP)'
              (?:(?:\.|^)?{LABELS:x}(\)\Z)?)?
              (?:(?:\.|^){PLATFORM})?
              (?:(?:\.|\/|^)
                  (?:(?P<FAMILY>[-\w]+))
                  (?:\.(?P<VARIANT>\w+))?
                  (?:\.(?P<SUFFIX>\w+))?)?$"""


class Rising(ClassificationDecoder):
    pattern = rf"""^
            {LABELS:x}?
            (?:
                (?:(?:^|\/|\.){PLATFORM}) |
                (?:(?:\.|\/)(?P<FAMILY>[iA-Z][\-\w]+))
            )*
            (?:(?P<VARIANT>(?:[#@!.][a-zA-Z0-9]+)*?)%?)?$"""

    @property
    def name(self) -> str:
        keys = tuple(map(self.get, ('FAMILY', 'VARIANT')))
        return ''.join((keys if all(keys) else self.source))


class Virusdie(ClassificationDecoder):
    pattern = rf"""^
        (?:{HEURISTICS})?
        (?:(?:\A|\b|\.)(?:{LANGS}|{LABELS}))*
        (?:(?:\A|\b|\.){IDENT})?
    $"""


class URLHaus(ClassificationDecoder):
    pattern = rf"""^
        (({LABELS})(\.)?)?
        (?P<FAMILY>[\s\w]+)
    $"""
