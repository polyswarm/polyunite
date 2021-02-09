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
from .utils import antecedent, group


def extract_vocabulary(vocab, recieve=lambda m: next(m, None)):
    """Call `recieve` with a generator of all `vocab`'s matching label names"""
    sublabels = list(vocab.sublabels)
    return property(lambda self: recieve(label for label in sublabels if label in self))


EICAR_PATTERN = re.compile(
    r'.*(?P<FAMILY>(?P<EICAR>\L<eicarvariants>))', eicarvariants=['EICAR', 'eicar', 'Eicar']
)
REVERSE_NAME_REGEX = re.compile(r'(?r)(?:[A-Z]+[-])?[A-Z][-_\w]{2,}(?:[.-][A-Z]+)?')


class Classification(collections.UserDict):
    pattern: 'ClassVar[str]'
    regex: 'ClassVar[re.Pattern]'
    match: 're.Match'
    source: 'str'

    def __init__(self, name: str):
        try:
            self.match = EICAR_PATTERN.match(name, concurrent=True) or self.regex.fullmatch(
                name,
                timeout=1,
                concurrent=True,
            )
            super().__init__({k: v for k, v in self.match.capturesdict().items() if v})
        except (AttributeError, TypeError):
            raise MatchError(name, self.av_vendor)

    @property
    def source(self):
        return self.match.string

    @classmethod
    def __init_subclass__(cls):
        cls.regex = re.compile(
            cls.pattern,
            re.ASCII | re.VERBOSE,
            suffixes=list(SUFFIXES.entries),
            ignore_unused=True
        )
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
        {IDENT([r'(?&LANGS)', r'(?&MACROS)', r'[a-z]+', r'[A-Z]{3}', r'[A-Z][a-z]{2}'], [r'[.]ali[0-9a-f]+', '[.]None'])}
    )?
    $"""


class ClamAV(Classification):
    pattern = rf"""^
    (?:BC|Clamav)?
    (?|
        ((\.|^)(
            {PLATFORM}
            | {HEURISTICS}
            | {LABELS}
            | {OBFUSCATIONS}
            | Revoked[.]Certificate
        ))*?
        | Blacklist[.]CRT
    )
    (?P<NAME>
        (([./]|^){FAMILY_ID(
                r'[A-Z](?:[[:alnum:]]|_)+',
                r'Test[.]File',
                r'[[:alpha:]]+(?=-)',
                r'[A-Z]{3}',
                r'[0-9]+[A-Z][[:alpha:]]+',
            )})?
        {VARIANT_ID(r'([-.:][[:xdigit:]]+)?-[0-9]+(?:-[0-9])?',
                    r'/CRDF(?:-[[:alnum:]])?')}
    )
    $"""


class DrWeb(Classification):
    pattern = rf"""^
    (?:(?|probably|modification\s of|modification|possible|possibly)\s)?
    (?:(?:\b|[.])(?:{LABELS}(-?(?&LABELS))?|{PLATFORM}))*
    (?:(?:\b|[.]) # MulDrop6.38732 can appear alone or in front of another `.`
        {IDENT([r"PWS[.][[:alnum:]]+", r"[A-Z][a-z]{2}"], [r'[.]Log'])}
    )?
    $"""


class Ikarus(Classification):
    pattern = rf"""^
    (
        (?:[.:]|^)
        (?:
            {LABELS}(-?(?&LABELS)|[a-zA-Z0-9]+)?
            | {PLATFORM}
            | AD
            | Patched
            | FTP
            | X2000M
        )
    )*
    (?:
        (?:^|[.])
        (?P<NAME>
            (?: {FAMILY_ID(
                    r'(?P<HEURISTICS>NewHeur_[a-zA-Z0-9_-]+)',
                    r'(?P<HEURISTICS>Agent[.][A-Z]+)',
                    r'[A-Z]{3}',
                    r'[A-Z][a-z]{1,2}',
                    r'(?&LANGS)',
                )}?
                {VARIANT_ID(
                    r'[.]([0-9]+|[a-z]+|[A-Z]+|[A-F0-9]+)',
                    r'[.][A-Z][a-z][a-z]',
                    r'[.]Gen[0-9]*',
                )}{{,2}}
              ))
    )?
    $"""


class Jiangmin(Classification):
    pattern = rf"""^
    (?:
        (?:[./:]|^)
        (?:
            {HEURISTICS}
            | Intended
            | Garbage
            | {LABELS}(-?(?&LABELS))?
            | {OBFUSCATIONS}
            | {PLATFORM}
        )
    )*
    (?P<NAME>
        (([./]|^){FAMILY_ID(r'cnPeace')})?
        {VARIANT_ID(r'[.][[:alnum:]]+$')}{{,2}})
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
    pattern = group(
        rf"""^
    ((?:^|[.]){PLATFORM}|Email|HTTP|{LABELS}(-?(?&LABELS))?)*
    (?P<NAME>
        (?:
            (?:[.]|^)
            {FAMILY_ID(
                r"[0-9A-Z][a-zA-Z0-9]_[0-9]",
                r'([0-9]{{,3}})[A-Z][A-Za-z][0-9]{{4}}',
                r'[A-Z]{3}',
                )}
        )?
        {VARIANT_ID(r'[.][[:alnum:]][!][[:alnum:]]')}{{,2}}
    )
    $""",
        r"(?P<NAME>(?P<FAMILY>(?:[0-9]+|[A-Z])\w{3,}))",
    )


class NanoAV(Classification):
    pattern = rf"""^
    ((?:[.-]|^)
        (?:
            {PLATFORM}
            | Riff
            | {LABELS}
            | {OBFUSCATIONS}
        )
    )*
    (?P<NAME>
        (([./]|^){FAMILY_ID(r'hidIFrame',
                            r'(?i:Iframe-scroll)',
                            r'[A-Z][[:alnum:]]+')})?
        {VARIANT_ID()}{{,2}}
    )
    $"""


class Qihoo360(Classification):
    pattern = rf"""^
    (?=[a-z](?i))
    {HEURISTICS}?
    (
        (?:[./-]|^)
        (?:
            Application
            | Sorter
            | AVE
            | (?<HEURISTICS>AutoVirus)
            | {PLATFORM}
            | {LABELS}
            | (QVM\d+([.]\d+)?([.]\p{{Hex_Digit}}+)?) # QVM40.1.BB16 or QVM9
        )
    )*
    (?P<NAME>
        ([./]{FAMILY_ID()})?
        (({VARIANT_ID()}{{,2}}))?
    )
    $"""


class QuickHeal(Classification):
    pattern = rf"""^
    (?:
        (?:[./]|^)
        (?:{PLATFORM}|{LABELS}(?&LABELS)?|Cmd)
    )*
    (?P<NAME>
        (?:
            (?:[./]|^)
            {FAMILY_ID(r'VirXXX-[A-Z]',
                       rf'(?P<{HEURISTICS.name}>Agent[.][[:alnum:]]+)')}
        )?
        {VARIANT_ID(
            r'[.]S[[:xdigit:]]+',
            r'[.][A-Z]+[0-9]+',
            r'[.][[:xdigit:]]+'
            )}{{,2}}
    )
    $"""


class Rising(Classification):
    pattern = rf"""^
    (?(DEFINE)
        (?P<FAMILY>{CVE_PATTERN}|[iA-Z][-\w]+?)
        (?P<PLATFORM>{PLATFORM}))
    # -----------------------------
    ((?:[.]|^){LABELS}(?:[-]?(?&LABELS))?)*
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
    (?:{PLATFORM}|{LABELS}([-]?(?&LABELS))?)[/]{PLATFORM}[.]
    (?P<NAME>
        {FAMILY_ID('[A-Z][A-Z]-[A-Z][[:alpha]]+')}
        {VARIANT_ID(r'[.][0-9]+')}{{,2}}
    )$"""


class Virusdie(Classification):
    pattern = rf"""^
    (?:(?:^|[.])(?:{PLATFORM}|{LABELS}([-]?(?&LABELS))?))*
    (?P<NAME>
        (?:
            (^|[.])
            {FAMILY_ID(r'Exec[.]Stdio', r'Iframe[.]dnnViewState')}
        )?
        {VARIANT_ID()}{{,2}}
    )
    $"""


class URLHaus(Classification):
    pattern = rf"""^
    (({LABELS})(\.|$))?
    (?P<FAMILY>[\s\w]+)?
    $"""
