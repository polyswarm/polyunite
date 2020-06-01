import collections
from contextlib import suppress
from typing import ClassVar, Dict

import regex as re

from polyunite.errors import MatchError
from polyunite.utils import colors
from polyunite.vocab import VocabRegex, group

from .registry import registry

# regular expressions which match 'vocabularies' of classification components
LABELS = VocabRegex.from_resource('LABELS')
LANGS = VocabRegex.from_resource('LANGS')
ARCHIVES = VocabRegex.from_resource('ARCHIVES')
MACROS = VocabRegex.from_resource('MACROS')
OSES = VocabRegex.from_resource('OPERATING_SYSTEMS')
HEURISTICS = VocabRegex.from_resource('HEURISTICS')
OBFUSCATIONS = VocabRegex.from_resource('OBFUSCATIONS')
SUFFIXES = VocabRegex.from_resource('SUFFIXES')
PLATFORM = group(OSES, ARCHIVES, MACROS, LANGS, HEURISTICS)


def IDENT(extra_families=[], extra_variants=[]):
    """Build a family & variant subpattern"""
    return r'(?P<NAME>{family}?{variant}{{,3}})'.format(
        family=group(
            r'(?:[i0-9]?[A-Z](?:[[:alpha:]]+){i<=1:\d}\d*?)',
            r'(?P<CVE>CVE-?\d{4}-?\d+){i<=1:[a-z0-9A-Z]}',
            *extra_families,
            name='FAMILY',
        ),
        variant=group(
            r'[.!#@-]?(?<=[.!#@-])(?-i:[A-Z]+|[a-z]+|[a-f0-9]+|[A-F0-9]+)',
            r'(?i:[.#@!-]?(?<=[.!#@-])\L<suffixes>)',
            *extra_variants,
            name='VARIANT'
        )
    )


def extract_vocabulary(vocab, recieve=lambda m: next(m, None)):
    """Call `recieve` with a generator of all `vocab`'s matching label names"""
    sublabels = vocab.sublabels
    return property(lambda self: recieve(label for label in sublabels if label in self))


class Classification(collections.UserDict):
    pattern: 'ClassVar[str]'
    regex: 'ClassVar[re.Pattern]'
    data: 'Dict[str, str]'
    match: 're.Match'

    def __init__(self, name: str):
        super().__init__()
        try:
            self.match = self.regex.fullmatch(name)
            self.data = {k: v for k, v in self.match.capturesdict().items() if v}
        except (AttributeError, TypeError):
            raise MatchError(name)

    operating_system = extract_vocabulary(OSES)
    language = extract_vocabulary(LANGS)
    macro = extract_vocabulary(MACROS)
    labels = extract_vocabulary(LABELS, recieve=set)

    @classmethod
    def __init_subclass__(cls):
        cls.regex = re.compile(
            cls.pattern,
            re.VERBOSE,
            suffixes=[
                "bit", "cl", "dam", "dha", "dll", "dr", "gen", "kit", "ldr", "m", "mm", "origin", "pak",
                "pfn", "plock", "plugin", "remnants", "rfn", "rootkit", "worm"
            ],
            ignore_unused=True
        )
        registry.register(cls, cls.__name__)

    @classmethod
    def from_string(cls, name: 'str') -> 'Classification':
        """Build a `Classification` from the raw malware name provided by this engine"""
        return cls(name)

    @classmethod
    def guess_heuristic(cls, name: 'str') -> 'bool':
        try:
            return cls.from_string(name).is_heuristic
        except MatchError:
            return False

    @property
    def source(self):
        return self.match.string

    def first(self, group, default=None):
        """Retrieve the first capture in `group`"""
        return next(iter(self.get(group, ())), default)

    def last(self, group, default=None):
        """Retrieve the last capture in `group`"""
        return next(iter(reversed(self.get(group, ()))), default)

    def lastgroups(self, *groups):
        """Iterator of the last capture in `groups`"""
        return (self[f][-1] for f in groups if f in self)

    @property
    def name(self) -> str:
        """'name' of the virus"""
        return next(self.lastgroups('CVE', 'FAMILY'), self.source)

    @property
    def av_vendor(self) -> str:
        """Engine / AV vendor's name"""
        return self.__class__.__name__

    @property
    def is_heuristic(self) -> bool:
        """Check if we've parsed this classification as a heuristic-detection"""
        return any(
            map(
                HEURISTICS.compile(1, 1).fullmatch,
                self.lastgroups(HEURISTICS.name, LABELS.name, 'VARIANT', 'FAMILY')
            )
        )

    def colorize(
        self,
        style={
            'NAME': colors.UNDERLINE,
            'FAMILY': colors.GREEN_FG,
            'VARIANT': colors.WHITE_FG,
            LABELS.name: colors.YELLOW_FG,
            ARCHIVES.name: colors.RED_FG,
            HEURISTICS.name: colors.MAGENTA_FG,
            MACROS.name: colors.UNDERLINE + colors.RED_FG,
            LANGS.name: colors.BLUE_FG,
            OSES.name: colors.CYAN_FG,
            OBFUSCATIONS.name: colors.WHITE_FG + colors.UNDERLINE,
        }
    ) -> str:
        """Colorize a classification string's parts which matched the labels in `STYLE`"""
        markers = list(self.source)
        for name, style in style.items():
            with suppress(IndexError):
                for start, end in self.match.spans(name):
                    markers[start] = style + self.source[start]
                    markers[end] = colors.RESET + self.source[end]
        return ''.join(markers) + colors.RESET


class Alibaba(Classification):
    pattern = rf"""^
        (?:(?:{OBFUSCATIONS}|{LABELS}*)[:])*
        (?:{PLATFORM}[/])*
        { IDENT([r"[a-z]+", r"[A-Z]{2}"], [r"[.]ali[0-9a-f]+"]) }?
    ?$"""


class ClamAV(Classification):
    pattern = rf"""^
        (?:(?P<PREFIX>BC|Clamav))?
        (?:(\.|^)(?:{PLATFORM}|{LABELS}|{OBFUSCATIONS}))*?
        (?:(\.|^)(?P<FAMILY>\w+)(?:(\:\w|\/\w+))*(?:-(?P<VARIANT>[\-0-9]+)))?$"""


class DrWeb(Classification):
    pattern = rf"""^
    (?:{HEURISTICS}(?:\s+(?:of\s*)?)?)?
              (?:(\.|\A|\b)(?:{LABELS}|{PLATFORM}))*
              (?:(\.|\b) # MulDrop6.38732 can appear alone or in front of another `.`
                  {IDENT()})?$"""


class Ikarus(Classification):
    pattern = rf"""^(not-a-virus:)? ({OBFUSCATIONS}\.)?
                    (({LABELS}(-\w+)?)\.)? (({PLATFORM})\.)? (?P<FAMILY>.*)?
                    $"""


class Jiangmin(Classification):
    pattern = rf"""^(?:{HEURISTICS}:?)?
              (?:(?:({LABELS}{{,2}})|{OBFUSCATIONS}|{PLATFORM})[./]|\b)+
              {IDENT(["cnPeace"], [r"[a-z]+[0-9]"])}?$"""


class K7(Classification):
    pattern = rf"""^(?:[-]?{LABELS})*
                    (?:\s*\(\s* (?P<VARIANT>[a-f0-9]+) \s*\))?$"""

    @property
    def name(self) -> str:
        # K7 does not work with family names
        return ''


class Lionic(Classification):
    pattern = rf"""^{LABELS}?
                    (?:(^|\.)(?:{PLATFORM}))?
                    (?:(?:\.|^){IDENT()})?$"""


class NanoAV(Classification):
    pattern = rf"""^
        (?:Marker[.])?
        (?:(?:\A|\.|\-)(?:{PLATFORM}|Text|{LABELS}))*
        (([.]|\A){IDENT()})$"""


class Qihoo360(Classification):
    pattern = rf"""
        ^(?:{HEURISTICS}(?:/|(?:(?<=VirusOrg)\.)))?
              (?:(?:Application|({PLATFORM})|{LABELS}|(QVM\d*(\.\d)?(\.[0-9A-F]+)?))([.]|\/|\Z))*
              (?<![A-Z](?i)){IDENT()}?$"""


class QuickHeal(Classification):
    pattern = rf"""
        ^(?:{HEURISTICS}\.)?
              (?:(?:{LABELS})+)?
              # This trailing (\)$) handle wierd cases like 'Adware)' or 'PUP)'
              (?:(\)$))?
              (?:(?:\.|^){PLATFORM})?
              (?:(?:\.|\/|^)
                  (?:(?P<FAMILY>[-\w]+))
                  (?:\.(?P<VARIANT>\w+))?
                  (?:\.(?P<SUFFIX>\w+))?)?$"""


class Rising(Classification):
    pattern = rf"""^
    (?(DEFINE)
        (?P<FAMILY>[iA-Z][\-\w]+?)
        (?P<PLATFORM>{PLATFORM}))

    (?:[.]?{LABELS})*
    (?:(?:\A|[.])(?&PLATFORM))*
    (?:
        [.](?&FAMILY) |
        [.](?&PLATFORM)/(?&FAMILY) |
        (?:[.](?&FAMILY))?/(?&PLATFORM)
    )?
    (?P<VARIANT>
        (?:
            [!]ET\#\d\d\% |
            [@][A-Z]+ |
            [!#.][a-z0-9]+ |
            [.][A-Z]+ |
            [.]\L<suffixes>
        ){{,2}}
        (?:(?:[!][0-9]+)?[.][A-F0-9]+)?
    )?
    $"""

    @property
    def name(self) -> str:
        """'name' of the virus"""
        return next(self.lastgroups('CVE', 'FAMILY', HEURISTICS.name), self.source)


class Virusdie(Classification):
    pattern = rf"""^
        (?:{HEURISTICS})?
        (?:(?:\A|\b|\.)(?:{PLATFORM}|{LABELS}))*
            (?i:(?:\A|\b|\.){IDENT()})?
    $"""


class URLHaus(Classification):
    pattern = rf"""^
        (({LABELS})(\.|$))?
        (?P<FAMILY>[\s\w]+)?
    $"""
