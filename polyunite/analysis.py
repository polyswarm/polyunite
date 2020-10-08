from typing import TYPE_CHECKING, Iterable, Union

from collections import defaultdict
from itertools import combinations

from .parsers import Classification


def guess_malware_name(classifications: Iterable[Union[str, 'Classification']]) -> str:
    """
    Returns the name with the smallest total distance edit distance from `classifications`
    """
    similarity: defaultdict = defaultdict(lambda: 0)

    def filtermap(cs):
        for c in cs:
            o = str(c.name if isinstance(c, Classification) else c or '')
            if len(o) > 2:
                yield o

    for x, y in combinations(filtermap(classifications), 2):
        d = _edit_distance(x, y, case_insensitive=True) ** 2
        similarity[x] += d
        similarity[y] += d

    return min(similarity.keys(), key=lambda k: similarity[k])


def _edit_distance(x: str, y: str, case_insensitive=False) -> float:
    """
    Levenshtein edit distance between two strings (`x` & `y`)
    """
    if not isinstance(x, str) or not isinstance(y, str):
        raise TypeError("Invalid arguments: type(x)=%s, type(y)=%s", type(x), type(y))

    if case_insensitive:
        x, y = map(str.lower, (x, y))

    if x == y:
        return 0.0

    if len(x) == 0:
        return len(y)

    if len(y) == 0:
        return len(x)

    v0 = [0] * (len(y)+1)
    v1 = [0] * (len(y)+1)

    for i in range(len(y) + 1):
        v0[i] = i

    for i in range(len(x)):
        v1[0] = i + 1

        for j in range(len(y)):
            cost = 1

            if x[i] == y[j]:
                cost = 0

            v1[j + 1] = min(v1[j] + 1, v0[j + 1] + 1, v0[j] + cost)

        v0, v1 = v1, v0

    return v0[len(y)]


__all__ = ['guess_malware_name']
