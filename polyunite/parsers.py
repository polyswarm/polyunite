from typing import ClassVar, Set

from collections.abc import Mapping
import regex as re

from polyunite.errors import MatchError
from polyunite.utils import colors
from polyunite.vocab import (
    ARCHIVES,
    FAMILY_ID,
    HEURISTICS,
    IDENT,
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
            self._groups = {k: None for k, v in self.match.capturesdict().items() if v}.keys()
        except (AttributeError, TypeError):
            raise MatchError(name, self.registration_name())

    @property
    def source(self) -> 'str':
        return self.match.string

    @classmethod
    def __init_subclass__(cls):
        pat = '{}|{}'.format(
            r'(^.*(?P<EICAR>(?i:eicar)).*$)',
            cls.pattern,
        )
        cls.regex = re.compile(pat, re.ASCII | re.VERBOSE)
        EngineRegistry.register(cls, cls.__name__)

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
        labels = set(label for label in LABELS.sublabels if label in self)
        if self.is_CVE:
            labels.add('exploit')
            labels.add('CVE')
        return labels

    @property
    def name(self) -> str:
        """'name' of the virus"""
        family = self.family

        if family is not None:
            return family

        return self.taxon

    @property
    def family(self):
        if self.is_EICAR:
            return 'EICAR'

        if self.is_CVE:
            return self.extract_CVE()

        if 'FAMILY' in self:
            return self['FAMILY']

    @property
    def taxon(self):
        if 'VEID' in self:
            return self.source[0:self.match.start('VEID')]
        else:
            return self.source

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
        return self.match.expandf("CVE-{CVEYEAR[0]}-{CVENTH[0]}").rstrip('-')

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
    (({OBFUSCATIONS}|{LABELS})*[:])?
    ({PLATFORM}[/])?
    (
        {IDENT([LANGS, MACROS, r'[a-zA-Z0-9]{3,}'], [r'[.]ali[0-9a-f]+', '[.]None'])}
    )?
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
    ((?|probably|modification\s of|modification|possible|possibly)\s)?
    (
        (^|\b|[.-])
        ( {LABELS}
          | {PLATFORM}
          | MGen
          | Ear
        )
    )*
    (?P<VEID>
        (
            ([.]|\b|^)
            {FAMILY_ID(
                r'PWS[.][[:alnum:]]+',
                r'^[A-Z][[:alnum:]]{1,2}(?=[.])',
                r'^[A-Z][[:alnum:]][a-zA-Z0-9-_.]+[A-Z][[:alnum:]]$',
            )}
        )?
        {VARIANT_ID(r'[.]Log')}{{,2}}
    )
    $"""


class Ikarus(Classification):
    pattern = rf"""^
    (
        ([.:-]|^)
        (
            {LABELS}*
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
            | WScr
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
       ([.]((?&OPERATING_SYSTEMS)|(?&LANGS)|(?&MACROS)|(?&OBFUSCATIONS)))?
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
                r'[A-Z][a-z]',
                r'(?&LANGS)',
                r'(?&MACROS)',
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
    (?=[a-z](?i))
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
            | (QVM\d+([.]\d+)?([.]\p{{Hex_Digit}}+)?) # QVM40.1.BB16 or QVM9
        )
    )*
    (?P<VEID>
        (
            ([./]|^)
            {FAMILY_ID()}?
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
                | (?&LANGS)
                | (?&ARCHIVES)
                | (?&HEURISTICS)
                | (?&MACROS)
                | (?&OPERATING_SYSTEMS)
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
        (?|{PLATFORM}|{LABELS})
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
            ({FAMILY_ID()}|.+?)
        )
        {VARIANT_ID()}{{,2}}
    )
    $"""


class URLHaus(Classification):
    pattern = rf"""^
    (({LABELS})(\.|$))?
    (?P<VEID>(?P<FAMILY>[\s\w]+)?)
    $"""
