from typing import ClassVar, Set

from collections.abc import Mapping
import regex as re

from polyunite.errors import MatchError
from polyunite.utils import colors
from polyunite.vocab import (
    ARCHIVES,
    FAMILY_ID,
    HEURISTICS,
    LABELS,
    LANGS,
    MACROS,
    OBFUSCATIONS,
    OSES,
    PLATFORM,
    VARIANT_ID,
)

from .registry import EngineRegistry
from .utils import group


def extract_vocabulary(vocab, recieve=lambda m: next(m, None)):
    """Call `recieve` with a generator of all `vocab`'s matching label names"""
    sublabels = list(vocab.sublabels)
    return property(lambda self: recieve(label for label in sublabels if label in self))


class Classification(Mapping):
    pattern: 'ClassVar[str]'
    regex: 'ClassVar[re.Pattern]'
    match: 're.Match'
    _groups: 'Set[str]'

    def __init__(self, name: str):
        try:
            self.match = self.regex.fullmatch(name, timeout=1, concurrent=False)
            self._groups = {k for k, v in self.match.capturesdict().items() if any(v)}
        except (AttributeError, TypeError):
            raise MatchError(name, self.registration_name())

    @property
    def source(self) -> 'str':
        return self.match.string

    @classmethod
    def __init_subclass__(cls):
        cls.regex = cls._compile_pattern()
        EngineRegistry.register(cls, cls.registration_name())

    @classmethod
    def _compile_pattern(cls):
        pat = group(r'.*(?P<EICAR>(?i:EICAR)).*', cls.pattern)
        return re.compile(pat, re.ASCII | re.VERBOSE | re.V1)

    def __getitem__(self, k):
        if k in self:
            return self.match[k]
        raise KeyError

    def __contains__(self, k):
        return k in self._groups

    def __iter__(self):
        return iter(self._groups)

    def __len__(self):
        return len(self._groups)

    @classmethod
    def from_string(cls, name: 'str') -> 'Classification':
        """Build a `Classification` from the raw malware name provided by this engine"""
        return cls(name)

    operating_system = extract_vocabulary(OSES)
    language = extract_vocabulary(LANGS)
    macro = extract_vocabulary(MACROS)

    @property
    def labels(self):
        if self.is_EICAR:
            return {'nonmalware'}
        labels = set(LABELS.sublabels) & set(self._groups)
        if self.is_CVE:
            return labels | {'exploit', 'CVE'}
        return labels

    @property
    def name(self) -> str:
        """'name' of the virus"""
        return self.family or self.taxon

    @property
    def family(self):
        if self.is_EICAR:
            return 'EICAR'
        elif self.is_CVE:
            return self.extract_CVE()
        return self.get('FAMILY', None)

    @property
    def taxon(self):
        try:
            start = min(self.match.starts('VARIANT'), default=None)
        except IndexError:
            return self.source

        return self.source[0:start]

    @classmethod
    def registration_name(cls):
        """Engine / AV vendor's name"""
        return cls.__name__

    @property
    def is_EICAR(self):
        return 'EICAR' in self

    @property
    def is_CVE(self):
        return 'CVE' in self

    def extract_CVE(self):
        return self.match.expandf("CVE-{CVEYEAR[0]}-{CVENTH[0]}")

    @property
    def is_heuristic(self) -> bool:
        """Check if we've parsed this classification as a heuristic-detection"""
        last_matches = map(self.get, (HEURISTICS.name, LABELS.name, 'VARIANT', 'FAMILY'))
        return any(map(HEURISTICS.compile(1, 1).fullmatch, filter(None, last_matches)))

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


class Alibaba(Classification):
    pattern = rf"""^
    (({PLATFORM}|{LABELS}([-]?(?&LABELS))?|[^:]*)([:]|$))?
    {PLATFORM}[/]
    (?P<VEID>
        {FAMILY_ID('(?&LABELS)', r'[[:alnum:]]+')}
        {VARIANT_ID(r'[.][[:xdigit:]]{1,10}', r'[.]None', r'[.]ali[[:xdigit:]]+')}{{,3}}
    )
    $"""


class ClamAV(Classification):
    pattern = rf"""^
    (Clamav|Urlhaus)?
    (
        ([.]|^)
        (
            {PLATFORM}
            | {LABELS}
            | Legacy
        )
    )*
    (?P<VEID>
        (
            ([.]|^)
            {FAMILY_ID(r'Blacklist[.]CRT[.][[:xdigit:]]+', '[A-Z][[:alpha:]]+', r'[A-Z0-9][[:alnum:]]+(?=-)')}
        )?
        {VARIANT_ID(r'-[0-9]+',
                    r':[0-9]',
                    r'[.][0-9]+(?=-[0-9])',
                    r'/CRDF(-[[:alnum:]])?',
                    r'[.]Extra_Field')}*
    )
    $"""


class DrWeb(Classification):
    pattern = rf"""^
    ((probabl[ey]|modification(\ of)?|possibl[ey]))?
    (
        (^|[.-]|\ )
        (
          (?!PWS[.]){LABELS}(?&LABELS)?
          | {PLATFORM}
          | Sector
          | MGen
          | Ear
        )
    )*
    (?P<VEID>
        (
            ([.]|^)
            (
                (?P<FAMILY>(?P<password_stealer>PWS[.][A-Z][[:alnum:]]+))
                | {FAMILY_ID(r'[A-Z][[:alnum:]]{1,2}(?=[.]|$)')}
            )
        )?
        {VARIANT_ID(r'[.]Log')}*
    )
    $"""


class Ikarus(Classification):
    pattern = rf"""^
    (
        ([.:-]|^)
        (
            {LABELS}(-?(?&LABELS))?
            | (BehavesLike)?{PLATFORM}
            | AIT
            | ALS
            | BDC
            | Click
            | (Client|Server)-[[:alpha:]]+
            | Conduit
            | Damaged
            | DongleHack
            | Fraud
            | Fake
            | FTP
            | MalwareScope
            | Optional
            | Patch
            | PCK
            | SPR
            | ToolKit
            | Troja
            | WordPress
            | X2000M
            | Equation
        )
    )*
    (?P<VEID>
      (
          (^|[.:])
          {FAMILY_ID(
            r'(?P<HEURISTICS>NewHeur_[a-zA-Z0-9_-]+)',
            r'^[A-Z][a-zA-Z0-9_-]+$',
            r'PDF-[[:alnum:]]+',
           )}
       )?
       {VARIANT_ID(
                r'[.]SuspectCRC',
                r'20[0-9]{2}-[0-9]{1,6}',
                r'[-][A-Z]',
                r'[-][0-9]+$',
                r'[.](?|Dm|Ra)',
                r'[.]gen[0-9]x',
                r'[.][A-Z]{2,3}',
                r'[.][A-Z][a-z]{2}',
                r'[.][A-Z]{1,2}[0-9]*',
                r'[.][A-Z][a-z0-9]$',
                r'[:][[:alpha:]]+',
       )}{{,3}}
       ([.]{PLATFORM})?
    )?
    $"""


class Jiangmin(Classification):
    pattern = rf"""^
    (
        ([./:]|^)
        (
            {HEURISTICS}
            | Intended
            | Garbage
            | Riot
            | {LABELS}(-?(?&LABELS))?
            | {OBFUSCATIONS}
            | {PLATFORM}
        )
    )*
    (?P<VEID>
        (([./]|^){FAMILY_ID(r'[A-Z][a-z]+-[0-9]')})?
        {VARIANT_ID(r'[.][[:alnum:]]+$', '[.][A-Z][a-z]$')}{{,2}})
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
    (
        (^|[.])
        (
            {PLATFORM}
            | Email
            | W
            | pcap
            | HTTP
            | Shell
            | {LABELS}(-?(?&LABELS))?
        )
    )*
    (?P<VEID>
        (
            ([.]|^)
            {FAMILY_ID(
                r"[0-9A-Z][a-zA-Z0-9]_[0-9]",
                r'^[a-zA-Z0-9_]+$',
                r'([0-9]{,3})[A-Z][A-Za-z][0-9]{4}',
                r'[A-Z][a-z]'
             )}
        )?
        {VARIANT_ID(r'[.][[:alnum:]][!][[:alnum:]]$')}*
    )
    $"""


class NanoAV(Classification):
    pattern = rf"""^
    (([.-]|^)
        (
            {PLATFORM}
            | Riff
            | {LABELS}
            | {OBFUSCATIONS}
        )
    )*
    (?P<VEID>
        (
            ([./]|^)
            {FAMILY_ID(r'hidIFrame',
                            r'Iframe-scroll',
                            r'[A-Z][[:alnum:]]+',
                            r'[0-9]+[a-z]{2,}[0-9]*',
            )}
        )?
        {VARIANT_ID()}{{,2}}
    )
    $"""


class Qihoo360(Classification):
    pattern = rf"""^
    (?i)
    {HEURISTICS}?
    (
        ([./-]|^)
        (
            Application
            | Sorter
            | AVE
            | (?<HEURISTICS>AutoVirus)
            | {PLATFORM}
            | {LABELS}
            | (QVM\d+([.]\d+)?([.][[:xdigit:]]+)?) # QVM40.1.BB16 or QVM9
        )
    )*
    (?P<VEID>
        (
            ([./]|^)
            {FAMILY_ID(r'(?-i:[A-Z][a-z]{1,2})')}?
        )?
        {VARIANT_ID()}{{,2}}
    )
    $"""


class QuickHeal(Classification):
    pattern = rf"""^
    (
        ([./]|^)
        ({PLATFORM}|{LABELS}(?&LABELS)?|Cmd|PIF|alware)
    )*
    (?P<VEID>
        (?![.]S[[:xdigit:]]+\b)
        (
            ([./]|^)
            {FAMILY_ID(
                r'[0-9]+[A-Z][a-z]+',
                r'[A-Z][a-z]+[0-9]+',
            )}
        )?
        {VARIANT_ID(
            r'[.]HTML[.][A-Z]',
            r'[-][A-Z]',
            r'[.][A-Z][[:xdigit:]]+$',
            r'[.][A-Z]{1,2}[0-9]{1,2}',
            r'[.][a-z0-9]{2,3}+'
            )}{{,2}}
    )
    $"""


class Rising(Classification):
    pattern = rf"""^
    (
        ([./-]|^)
        (
            {LABELS}
            | {PLATFORM}
            | BL
            | KL
            | Junk
        )
    )*
    (?P<VEID>
        (
            ([./-]|^)
            {FAMILY_ID(
                r'[0-9]+[A-Z][[:alpha:]]+',
                r'[A-Z][[:alpha:]]+-([A-Z][[:alpha:]]*|[0-9]+)',
                r'(?# [XXX] e.x `Trojan.Win32.fedoN.cf`)'
                r'fedoN',
                r'(?# e.x `Malware.Generic[Thunder]!1.A1C4`)'
                r'[A-Z][[:alnum:]]+[(][[:alnum:]]+[)]',
                r'(?# e.x `Worm.Nuj!8.2AD` & `Worm.Oji/Android!8.10B72`)'
                r'[A-Z][[:alpha:]]{1,2}(?=[/!.-])',
                r'(?# e.x `Malware.n!8.FB62`)'
                r'(?<=[.])[a-z](?=!)',
            )}
        )?
        ([/]
            (
                (?&LABELS)
                | {PLATFORM}
                | Source
                | AllInOne
                | SLT
                | APT
            )
        )?
        {VARIANT_ID(
            r'[!][[:alnum:]][.][[:xdigit:]]+',
            r'[.][[:alnum:]][!][[:xdigit:]]+',
            r'[!][[:xdigit:]]{1,5}$',
            r'[.][A-F0-9]{4,}$',
            re.escape('[HT]'),
            r'[#][0-9]{1,3}%',
            r'[!]ET',
            r'[#][A-Z][A-Z0-9]+',
            r'/[A-Z][A-Z0-9]',
            r'[!]tfe',
            r'[@](CV|EP|URL|VE)',
        )}*
    )
    $"""


class Tachyon(Classification):
    # https://tachyonlab.com/en/main_name/main_name.html
    pattern = rf"""^
    (
        (^|[-])
        ({PLATFORM}|{LABELS})
    )+
    (/{PLATFORM})
    (?P<VEID>
        (
            [.]
            {FAMILY_ID(r'[A-Z]{2}[-][A-Z][[:alpha:]]+')}
        )
        {VARIANT_ID(r'[.][0-9]+')}{{,2}}
    )$"""


class Virusdie(Classification):
    pattern = rf"""^
    (
        (^|[.-])
        {PLATFORM}|{LABELS}
    )*
    (?P<VEID>
        (
            (^|[.])
            (
                {FAMILY_ID()}
                | .+
            )
        )?
        {VARIANT_ID()}*
    )
    $"""


class URLHaus(Classification):
    pattern = rf"""^
    {LABELS}?
    (?P<VEID>
        (
            (^|[.])
            {FAMILY_ID()}
        )?
        {VARIANT_ID()}*
    )
    $"""
