from typing import TYPE_CHECKING, Callable, Iterable, Optional, Tuple, Union

from collections import Counter, UserDict
import math
import rapidfuzz

from .utils import flatmap
from .vocab import (
    ARCHIVES,
    HEURISTICS,
    LABELS,
    LANGS,
    MACROS,
    OBFUSCATIONS,
    OSES,
)

if TYPE_CHECKING:
    from polyunite.parsers import Classification


class Analyses(UserDict):
    """
    Analysis of engines -> family mappings produced by multiple AV analyses on a single file.
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
        ctr = Counter(sorted(filter(None, flatmap(key, self.values()))))
        return [elt for elt, _ in ctr.most_common(top_k)]

    def labels_summary(self, top_k=None):
        """
        Return the labels associated with these analyses:

        >>> analyses.labels_summary()
        ['trojan', 'security_assessment_tool']
        """
        return self.summarize(lambda o: o.labels, top_k=top_k)

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

            if len(name) <= 2:
                weight = 0
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
            matches = rapidfuzz.process.extract(name, names, scorer=rapidfuzz.fuzz.QRatio)
            return sum(score * weights[name] for _, score, _ in matches)

        return {n: edit_distance(n) for n in names}
