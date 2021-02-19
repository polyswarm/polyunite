from typing import TYPE_CHECKING, Callable, Iterable, Tuple, Union

from collections import Counter, UserDict
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
        return self.summarize(lambda o: o.labels, top_k=top_k)

    def infer_name(self, **kwargs):
        """
        Returns the name with the smallest total distance edit distance from `classifications`

        >>> registry.infer_name({'Ikarus': 'Zeus', 'Rising': 'zeus', 'Qihoo360': 'zbot',
                                  'Virusdie': 'Zeus-Trojan', 'QuickHeal': 'Agent'})
        Zeus
        """
        return self._weighted_name_inference(self._weighted_names(**kwargs))

    def _weighted_names(
        self,
        weights={},
        name_weights={
            LABELS.compile(1, 0).fullmatch: 0.80,
            HEURISTICS.compile(1, 0).fullmatch: 0.55,
            OBFUSCATIONS.compile(1, 0).fullmatch: 0.55,
            LANGS.compile(1, 0).fullmatch: 0.20,
            ARCHIVES.compile(1, 0).fullmatch: 0.20,
            MACROS.compile(1, 0).fullmatch: 0.20,
            OSES.compile(1, 0).fullmatch: 0.20,
        },
        taxon_weight=0.35,
    ):
        for engine, clf in self.items():
            weight = weights.get(engine, 1.0)

            name = clf.family

            if name is None:
                name = clf.taxon
                weight *= taxon_weight

            # Only consider strings longer than 2 chars
            if isinstance(name, str):
                for predicate, adjustment in name_weights.items():
                    if predicate(name):
                        weight *= adjustment
                        break

                yield name, weight

    def _weighted_name_inference(self, names: Iterable[Tuple[str, float]]) -> str:
        items = tuple((n, w) for n, w in names if w > 0 and len(n) > 2)
        names = tuple(n for n, w in items)
        weights = dict(items)

        def edit_distance(name):
            matches = rapidfuzz.process.extract(name, names, scorer=rapidfuzz.fuzz.QRatio)
            return sum(score * weights[name] for _, score, _ in matches)

        if weights:
            return max(names, key=edit_distance)
