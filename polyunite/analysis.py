from typing import TYPE_CHECKING, Callable, Iterable, Optional, Tuple, Union

from collections import Counter, UserDict
from itertools import chain
import math
from operator import attrgetter
import rapidfuzz
import regex as re

from .utils import flatmap
from .vocab import (
    ARCHIVES,
    CVE_PATTERN,
    HEURISTICS,
    LABELS,
    LANGS,
    MACROS,
    MS_BULLETIN_PATTERN,
    OBFUSCATIONS,
    OSES,
)

if TYPE_CHECKING:
    from polyunite.parsers import Classification


class Analyses(UserDict):
    """
    Analysis of engines -> family mappings produced by multiple AV analyses on a single file.

    >>> analyses = Analyses({
        'Alibaba': 'Win32/SubSeven.6ca32fd3',
        'ClamAV': 'Win.Trojan.SubSeven-38',
        'DrWeb': 'BackDoor.SubSeven.145',
        'Jiangmin': 'Backdoor/SubSeven.22.a',
        'Lionic': 'Trojan.Win32.SubSeven.m!c',
        'NanoAV': 'Trojan.Win32.SubSeven.dqcy',
    })
    """
    def __init__(self, results):
        super().__init__(dict(results))

    def summarize(
        self,
        key: Callable[['Classification'], Union[Iterable[str], str]] = None,
        top_k: int = None,
    ):
        """
        Return an iterator of unique applications of ``key`` to the decoded malware family of each
        engine in ``results``. ``top_k`` selects only the most common k applications of key.
        """
        iterator = filter(None, flatmap(key, self.values()))
        return [elt for elt, _ in Counter(iterator).most_common(top_k)]

    def labels_summary(self, **kwargs):
        """
        Return the labels associated with these analyses:

        >>> analyses.labels_summary()
        ['trojan', 'security_assessment_tool']
        """
        return self.summarize(attrgetter('labels'), **kwargs)

    def platform_summary(self, **kwargs):
        """
        Return the platform (languages & macros) associated with these analyses:

        >>> analyses.platform_summary()
        ['JS', 'HTML', 'MSOffice']
        """
        return self.summarize(attrgetter('language', 'macro'), **kwargs)

    def behavior_summary(self, **kwargs):
        """
        Return the languages associated with these analyses:

        >>> analyses.behaviors_summary()
        ['CodeEncryption', 'Packing', 'AntiFirewall']
        """
        return self.summarize(attrgetter('obfuscations'), **kwargs)

    def infer_operating_system(self):
        """
        Return the labels associated with these analyses:

        >>> analyses.infer_operating_system()
        Windows
        """
        summary = self.summarize(attrgetter('operating_system'), top_k=1)
        return next(iter(summary), None)

    infer_os = infer_operating_system

    def infer_name(self, **kwargs):
        """
        Returns the name with the smallest total distance edit distance from `classifications`

        >>> analyses.infer_name()
        Emotet
        """
        return self._weighted_name_inference(self._weighted_names(**kwargs))

    def edit_distance(self, **kwargs):
        """
        Returns a dictionary of names with a number representing their relative similarity to every other name

        >>> analyses.infer_likelihoods()
        {'Emotet': 0.75, 'Nemucod': 0.35}
        """
        return self._weighted_name_likelihood(self._weighted_names(**kwargs))

    def name_similarity_metric(self, name, **kwargs):
        """
        Compares `name` to the inferred name, computing a similarity metric

        >>> analyses.name_similarity_metric('EmotetRI')
        85.71
        """
        return rapidfuzz.fuzz.QRatio(self.infer_name(**kwargs), name)

    def describe(self) -> Counter:
        """
        Return descriptive statistics
        """
        ctr = Counter()
        for engine, clf in self.items():
            ctr['total'] += 1

            if clf.is_EICAR:
                ctr['EICAR'] += 1
            if clf.is_heuristic:
                ctr['heuristic'] += 1
            if clf.is_paramalware:
                ctr['paramalware'] += 1
            if clf.is_nonmalware:
                ctr['nonmalware'] += 1

        return ctr

    def vulnerability_ids(self):
        """
        Gather all vulnerability IDs (e.g CVE, Microsoft Security Bulletins, etc.)

        >>> analyses.vulnerability_ids()
        {'CVE-2012-3127'}
        """
        return {
            vid
            for clf in self.values()
            for vid in (clf.vulnerability_id_cve(), clf.vulnerability_id_microsoft())
            if vid
        }

    def _weighted_names(
        self,
        weights={},
        name_weights={
            LABELS.compile(1, 0).fullmatch: 1 / 8,
            HEURISTICS.compile(1, 0).fullmatch: 1 / 4,
            OBFUSCATIONS.compile(1, 0).fullmatch: 1 / 4,
            LANGS.compile(1, 0).fullmatch: 1 / 8,
            ARCHIVES.compile(1, 0).fullmatch: 1 / 8,
            MACROS.compile(1, 0).fullmatch: 1 / 8,
            OSES.compile(1, 0).fullmatch: 1 / 8,
            re.compile(CVE_PATTERN, re.I).fullmatch: 1 / 2,
            re.compile(MS_BULLETIN_PATTERN, re.I).fullmatch: 1 / 2,
        },
        taxon_weight=1 / 2,
    ):
        for engine, clf in self.items():
            weight = weights.get(engine, 1.0)

            name = clf.family

            if name is None:
                name = clf.taxon
                weight *= taxon_weight

            if not isinstance(name, str):
                continue

            if len(name) < 2:
                weight = 0.0
            elif len(name) < 5:
                weight *= len(name) / 5
            elif len(name) > 10:
                # Lower the weight of names longer than 10 chars
                weight /= math.log(len(name), 10)

            # Match `name` against the pattern predicates in `name_weights`, adjusting appropriately
            if weight > 0:
                for predicate, adjustment in name_weights.items():
                    if predicate(name):
                        weight *= adjustment
                        break

            yield name, weight

    def _weighted_name_inference(self, names: Iterable[Tuple[str, float]]) -> Optional[str]:
        likelihood = self._weighted_name_likelihood(names)
        return max(likelihood.keys(), default=None, key=likelihood.__getitem__)

    def _weighted_name_likelihood(self, names: Iterable[Tuple[str, float]]) -> str:
        items = tuple((n, w) for n, w in names if w > 0)
        names = tuple(n for n, w in items)
        weights = dict(items)

        def edit_distance(name):
            matches = rapidfuzz.process.extract(
                name,
                names,
                scorer=rapidfuzz.fuzz.QRatio,
                score_cutoff=45,
            )
            return sum(score * weights[name] for _, score, _ in matches)

        return {n: edit_distance(n) for n in names}

    def __repr__(self):
        """
        .. example::

            Analyses(
                name=Gamedrop,
                total=5,
                paramalware=1,
                unique_weights={'Amonetize': 0.8, 'ELTdrop': 1.0},
                vulnerability_ids={'MS-08-14'},
                operating_system=['Windows'],
                labels=['dropper', 'adware', 'trojan']
            )
        """
        weighted_names = tuple(self._weighted_names())
        parts = [
            ('name', self._weighted_name_inference(weighted_names)),
            ('unique_weights', {k: round(v, 5)
                                for k, v in set(weighted_names)}),
            ('vulnerability_ids', self.vulnerability_ids()),
            ('platform', self.platform_summary()),
            ('behavior', self.behavior_summary()),
            ('operating_system', self.infer_operating_system()),
        ]
        parts.extend(self.describe().items())

        return '{}({})'.format(
            self.__class__.__name__,
            ', '.join('{}={}'.format(k, v) for k, v in parts if v),
        )
