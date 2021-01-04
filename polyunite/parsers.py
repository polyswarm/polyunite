from typing import ClassVar

import collections
import regex as re

from polyunite.errors import MatchError
from polyunite.utils import antecedent, colors
from polyunite.vocab import (
    ARCHIVES,
    CVE_PATTERN,
    FAMILY_ID,
    HEURISTICS,
    IDENT,
    LABELS,
    LANGS,
    MACROS,
    OBFUSCATIONS,
    OSES,
    PLATFORM,
    SUFFIXES,
    VARIANT_ID,
)

from .registry import registry


def extract_vocabulary(vocab, recieve=lambda m: next(m, None)):
    """Call `recieve` with a generator of all `vocab`'s matching label names"""
    sublabels = list(vocab.sublabels)
    return property(lambda self: recieve(label for label in sublabels if label in self))


EICAR_PATTERN = re.compile(
    r'.*(?P<FAMILY>(?P<EICAR>\L<eicarvariants>))', eicarvariants=['EICAR', 'eicar', 'Eicar']
)
REVERSE_NAME_REGEX = re.compile(r'(?r)([-_\w]{2,})')


class Classification(collections.UserDict):
    pattern: 'ClassVar[str]'
    regex: 'ClassVar[re.Pattern]'
    match: 're.Match'
    source: 'str'

    def __init__(self, name: str):
        try:
            self.match = EICAR_PATTERN.match(name) or self.regex.fullmatch(name)
            super().__init__({k: v for k, v in self.match.capturesdict().items() if v})
        except (AttributeError, TypeError):
            raise MatchError(name, self.av_vendor)

    @property
    def source(self):
        return self.match.string

    @classmethod
    def __init_subclass__(cls):
        cls.regex = re.compile(cls.pattern, re.VERBOSE, suffixes=list(SUFFIXES.entries), ignore_unused=True)
        registry.register(cls, cls.__name__)

    @classmethod
    def from_string(cls, name: 'str') -> 'Classification':
        """Build a `Classification` from the raw malware name provided by this engine"""
        return cls(name)

    def lastgroups(self, *groups):
        """Iterator of the last capture in `groups`"""
        return (self[f][-1] for f in groups if f in self)

    operating_system = extract_vocabulary(OSES)
    language = extract_vocabulary(LANGS)
    macro = extract_vocabulary(MACROS)

    @property
    def labels(self):
        if self.is_EICAR:
            return {'nonmalware'}
        labels = set(label for label in LABELS.sublabels if label in self)
        if self.is_CVE:
            labels.add('exploit')
            labels.add('CVE')
        return labels

    @property
    def name(self) -> str:
        """'name' of the virus"""
        if self.is_EICAR:
            return 'EICAR'

        if self.is_CVE:
            return self.extract_CVE()

        if 'FAMILY' in self:
            return next(self.lastgroups('FAMILY'))

        # Return the longest leftmost word if we haven't matched anything
        endpos = self.match.start('VARIANT') if 'VARIANT' in self else None
        match = REVERSE_NAME_REGEX.search(self.source, endpos=endpos)
        return match[0] if match else self.source

    @property
    def av_vendor(self) -> str:
        """Engine / AV vendor's name"""
        return self.__class__.__name__

    @property
    def is_EICAR(self):
        return self.match.re is EICAR_PATTERN

    @property
    def is_CVE(self):
        return 'CVE' in self

    def extract_CVE(self):
        return self.match.expandf("CVE-{CVEYEAR[0]}-{CVENTH[0]}").rstrip('-')

    @property
    def is_heuristic(self) -> bool:
        """Check if we've parsed this classification as a heuristic-detection"""
        last_matches = self.lastgroups(HEURISTICS.name, LABELS.name, 'VARIANT', 'FAMILY')
        return any(map(HEURISTICS.compile(1, 1).fullmatch, last_matches))

    def colorize(
        self,
        style={
            LABELS.name: colors.YELLOW_FG,
            HEURISTICS.name: colors.MAGENTA_FG,
            OSES.name: colors.CYAN_FG,
            OBFUSCATIONS.name: colors.PINK_FG,
            ARCHIVES.name: colors.RED_FG,
            MACROS.name: colors.ORANGE_FG,
            LANGS.name: colors.BLUE_FG,
            'FAMILY': colors.GREEN_FG,
            'VARIANT': colors.WHITE_FG,
        },
        reset=colors.RESET
    ) -> str:
        """Colorize a classification string's parts which matched the labels in `STYLE`"""
        markers = list(self.source)
        for name, style in style.items():
            try:
                for start, end in self.match.spans(name):
                    markers[start] = style + self.source[start]
                    markers[end] = reset + self.source[end]
            except IndexError:
                continue

        return ''.join(markers) + colors.RESET


class Generic(Classification):
    """
    Generic parser, may be applied as a fallback or if the engine is unknown
    """
    pattern = rf"""^
    ((\A|\s|\b|[^A-Za-z0-9])({LABELS}|{OBFUSCATIONS}|{PLATFORM}))*?
    {IDENT()}
    $"""


class Alibaba(Classification):
    pattern = rf"""^
    (({OBFUSCATIONS}|{LABELS})*[:])?
    ({PLATFORM}[/])?
    (?:
        ((?P<nonmalware>(?P<NAME>(?P<FAMILY>eicar[.]com))))|
        {IDENT([r'[a-z]+', r'[A-Z]{2}'], [r'[.]ali[0-9a-f]+'])}
    )?
    $"""


class ClamAV(Classification):
    pattern = rf"""^
    ((?P<PREFIX>BC|Clamav))?
    ((\.|^)({PLATFORM}|{LABELS}|{OBFUSCATIONS}))*?([.]|$)
    (?P<NAME>
        (?P<FAMILY>{CVE_PATTERN}|\w+)
        ((\:\w|\/\w+))*
        (-(?P<VARIANT>[\-0-9]+))
    )?
    $"""


class DrWeb(Classification):
    pattern = rf"""^
    ({HEURISTICS}(\s+(of\s*)?)?)?
    ((\A|\b|[.])({LABELS}|{PLATFORM}))*
    ((\b|[.]) # MulDrop6.38732 can appear alone or in front of another `.`
        {IDENT()}
    )?
    $"""


class Ikarus(Classification):
    pattern = rf"""^
    ({HEURISTICS}\:?)?
    ((\A|[.]|\b)(-?{LABELS}|{OBFUSCATIONS}|{PLATFORM}|Patched))*
    ((\A|[.]|\b)
        (?P<NAME>
            (?P<FAMILY>{CVE_PATTERN}|BO|([i0-9]?[A-Z][\w_-]{{2,}}))?
            (?P<VARIANT>
                [.]([0-9]+|[a-z]+|[A-Z]+|[A-F0-9]+) |
                (?i:[.#@!]\L<suffixes>)
             ){{,2}}
        )
        ([.]({OSES}|{LANGS}|{MACROS}|{HEURISTICS}))?
    )?
    $"""


class Jiangmin(Classification):
    pattern = rf"""^
    ({HEURISTICS}:?)?
    ((({LABELS}{{,2}})|{OBFUSCATIONS}|{PLATFORM})[./]|\b)+
    {IDENT(["cnPeace", r"[A-Z][a-z]+-[0-9]"], [r"[a-z]+[0-9]"])}?
    $"""


class K7(Classification):
    pattern = rf"""^
    ([-]?{LABELS})*
    (\s*\(\s* (?P<VARIANT>[a-f0-9]+) \s*\))?
    $"""

    @property
    def name(self) -> str:
        # K7 does not work with family names
        if self.is_EICAR:
            return 'EICAR'

        return re.sub(r'^([-_\w]+) \(.*\)', r'\g<1>', self.source)


class Lionic(Classification):
    pattern = rf"""^
    {LABELS}?
    ((\A|[.]){PLATFORM})*
    ((\A|[.]){IDENT()})?
    $"""


class NanoAV(Classification):
    pattern = rf"""^
    (?:Marker[.])?
    (({PLATFORM}|Text|{LABELS}|{OBFUSCATIONS})(?:$|[.-]))*
    ({IDENT(["hidIFrame", "(?i:Iframe-scroll)", r"[A-Z][a-z]+[-][A-Z][a-z]+"])})
    $"""


class Qihoo360(Classification):
    pattern = rf"""^
    ({HEURISTICS}[/.])?
    (
        (?:
            (Application) |
            ({PLATFORM}) |
            ({LABELS}) |
            (QVM\d+([.]\d+)?([.]\p{{Hex_Digit}}+)?) # QVM40.1.BB16 or QVM9
        )
        ([./]|$)
    )*
    (?<![A-Z](?i))
    {IDENT([r'([A-Za-z]+-[A-Za-z]+)'])}
    $"""


class QuickHeal(Classification):
    pattern = rf"""^
    ({HEURISTICS}\.)?
        (([.]|\/|^)(?:{PLATFORM}|{LABELS}+(?!\w)))*
        # This trailing (\)$) handle wierd cases like 'Adware)' or 'PUP)'
        ((\)$))?
        (
            ([./]|^)
            {IDENT([r'VirXXX-[A-Z]'], [r'[.][[:xdigit:]]+'])}
        )?
    $"""


class Rising(Classification):
    pattern = rf"""^
    (?(DEFINE)
        (?P<FAMILY>{CVE_PATTERN}|[iA-Z][-\w]+?)
        (?P<PLATFORM>{PLATFORM}))
    # -----------------------------
    ([.]?{LABELS})*
    ((\A|[.])(?&PLATFORM))*
    (?|
        [.](?&FAMILY) |
        [.](?&PLATFORM)/(?&FAMILY) |
        ([.](?&FAMILY))?/(?&PLATFORM)
    )?
    (?P<VARIANT>
        (?|
           [!]   ET\#\d\d\% |
           [@]   [A-Z]+ |
           [!#.] [a-z0-9]+ |
           [.]   [A-Z]+ |
           (?i:\L<suffixes>)
        ){{,2}}
        ({antecedent:([!][0-9]+)}?[.][A-F0-9]+)?
    )?
    $"""


class Tachyon(Classification):
    # https://tachyonlab.com/en/main_name/main_name.html
    pattern = rf"""^
    (?:
        (?<{HEURISTICS.name}>Abuse-Worry>) |
        (\A|-){LABELS}
    )*
    /(?:(?:{PLATFORM}|\w+)[.-])?
    (?P<NAME>
        {FAMILY_ID([r'(?!CVE-)[-a-zA-Z0-9]{4,}'])}
        ([.](?P<SIZE>[0-9]+))?
        ({VARIANT_ID([r'[.]Zen'])}{{,2}}?)?
    )$"""


class Virusdie(Classification):
    pattern = rf"""^
    ({HEURISTICS})?
    ((\A|[.])({PLATFORM}|{LABELS}))*
    (?i:(\A|[.]){IDENT()})?
    $"""


class URLHaus(Classification):
    pattern = rf"""^
    (({LABELS})(\.|$))?
    (?P<FAMILY>[\s\w]+)?
    $"""
