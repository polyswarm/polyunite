from __future__ import annotations
from typing import ClassVar, Set

from collections.abc import Mapping
import regex as re
from sys import intern
import logging

from ..errors import MatchError
from ..registry import EngineRegistry
from ..utils import colors, group
from ..vocab import (
    VocabRegex,
    EICAR_GROUP_NAME,
    ARCHIVES,
    HEURISTICS,
    LABELS,
    LANGS,
    MACROS,
    OBFUSCATIONS,
    OSES,
)

log = logging.getLogger(__name__)

def extract_vocabulary(vocab, recieve=lambda m: next(m, None)):
    """Call `recieve` with a generator of all `vocab`'s matching label names"""
    def driver(self):
        tags = self._fetch()
        if vocab in tags:
            return tags[vocab]
        else:
            return None

    return property(driver)



class Classification(Mapping):
    __patterns__: 'ClassVar[Iterable[str]]'
    pattern: 'ClassVar[str]'
    regex: 'ClassVar[re.Pattern]'
    match: 're.Match'
    _groups: 'Set[str]'

    def __init__(self, name: str | list[str]):
        self.families = []
        try:
            if isinstance(name, list):
                self.families = name
                name = ','.join(self.families)
            self.match = self.regex.fullmatch(name, timeout=1, concurrent=False)
            self._groups = frozenset(k for k, v in self.match.capturesdict().items() if v)
        except (AttributeError, TypeError):
            raise MatchError(name, self.__class__.__name__)

    @property
    def source(self) -> 'str':
        """Source name"""
        return self.match.string

    @classmethod
    def __init_subclass__(cls):
        cls.regex = cls._compile_pattern()
        cls.registration = EngineRegistry.register(cls, cls.__name__)

    def _fetch(self):
        if 'tags' not in self.__dict__:
            all_tags = dict()
            for group in self._groups:
                if group in VocabRegex.groups:
                    for tagname, tags in VocabRegex.groups[group].tags.items():
                        all_tags.setdefault(tagname, set())
                        all_tags[tagname] |= set(tags)
            self.__dict__['tags'] = all_tags
        return self.__dict__['tags']

    @classmethod
    def _compile_pattern(cls):
        try:
            return re.compile(group(*cls.__patterns__), re.ASCII | re.VERBOSE | re.V1)
        except re.error as e:
            print(e.pattern)
            begin = e.pattern.rfind('\n', 0, e.pos)
            end = e.pattern.find('\n', e.pos)
            log.exception('%s:\n%s\n', e.msg, e.pattern[begin + 1:end])
            raise

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

    operating_system = extract_vocabulary('operating-system')
    archive_types = extract_vocabulary('archive-type')
    platform = extract_vocabulary('platform')
    language = extract_vocabulary('implementation-language')
    behaviors = extract_vocabulary('behavior')
    macro = extract_vocabulary('platform')
    # obfuscations = extract_vocabulary(OBFUSCATIONS, recieve=set)
    labels = extract_vocabulary('malware-type')

    @property
    def name(self) -> str:
        """'name' of the virus"""
        family = self.family
        if not family or len(family) <= 3:
            return self.taxon
        return family

    @property
    def family(self):
        """
        Captures the *named* malware family.
        """
        if self.is_EICAR:
            return 'EICAR'

        return self.vulnerability_id_cve() or \
                self.vulnerability_id_microsoft() or \
                self.get('FAMILY')

    @property
    def taxon(self):
        """
        Capture the common characteristics identified by this vendor (may include family)
        """
        try:
            start = min(self.match.starts('VARIANT'), default=None)
        except IndexError:
            return self.source

        return self.source[0:start]

    @property
    def is_EICAR(self):
        """Check if the EICAR test file was reported"""
        return EICAR_GROUP_NAME in self

    @property
    def is_heuristic(self) -> bool:
        """Check if we've parsed this classification as a heuristic-detection"""
        return 'HEURISTICS' in self

    @property
    def is_nonmalware(self) -> bool:
        return self.is_EICAR or 'nonmalware' in self

    @property
    def is_paramalware(self) -> bool:
        return self.is_nonmalware \
            or 'security_assessment_tool' in self \
            or 'greyware' in self \
            or 'parental_control' in self

    # noinspection PyDefaultArgument
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
            EICAR_GROUP_NAME: colors.BLUE_FG + colors.MAGENTA_BG,
            'nonmalware': colors.WHITE_FG + colors.MAGENTA_BG,
            'security_assessment_tool': colors.WHITE_FG + colors.BLACK_BG,
            'greyware': colors.BLACK_BG,
            'parental_control': colors.YELLOW_FG + colors.BLACK_BG,
            'microsoft_security_bulletin': colors.BOLD + colors.GREEN_FG,
            'CVE': colors.BOLD + colors.GREEN_FG,
            'FAMILY': colors.GREEN_FG,
            'VARIANT': colors.WHITE_FG,
        },
        reset=colors.RESET
    ) -> str:
        """
        Colorize a classification string's parts which matched the labels in `STYLE`
        """
        markers = list(self.source)
        for name, style in style.items():
            try:
                for start, end in self.match.spans(name):
                    markers[start] = style + self.source[start]
                    markers[end] = reset + self.source[end]
            except IndexError:
                continue

        return ''.join(markers) + colors.RESET

    def vulnerability_id_cve(self):
        """
        Captures any Common Vulnerabilities and Exposures (CVE) vulnerability identifier being referenced.

        .. seealso::

            `CVE Homepage <https://cve.mitre.org/>`_
        """
        if 'CVE' in self:
            try:
                return 'CVE-{CVEYEAR}-{CVENTH}'.format_map(self)
            except KeyError:
                return self.source

    def vulnerability_id_microsoft(self):
        """
        Captures any Microsoft Security Bulletin identifier being referenced.

        .. seealso::

            `MS Security Bulletin Homepage
            <https://docs.microsoft.com/en-us/security-updates/securitybulletins/securitybulletins>`_
        """
        if 'microsoft_security_bulletin' in self:
            try:
                return 'MS{MSSEC_YEAR}-{MSSECNTH}'.format_map(self)
            except KeyError:
                return self.source


__all__ = ['Classification']
