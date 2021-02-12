from typing import ClassVar, Set

from collections.abc import Mapping
import regex as re

from ..errors import MatchError
from ..registry import EngineRegistry
from ..utils import colors, group
from ..vocab import (
    ARCHIVES,
    HEURISTICS,
    LABELS,
    LANGS,
    MACROS,
    OBFUSCATIONS,
    OSES,
)


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
        return 'HEURISTICS' in self

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


__all__ = ['Classification']
