from typing import TYPE_CHECKING, Iterable, Union

from collections import defaultdict
from itertools import combinations

from .parsers import Classification


def guess_malware_name(classifications: Iterable[Union[str, 'Classification']]):
    """
    Returns the name with the smallest total distance edit distance from `classifications`
    """
    similarity: defaultdict = defaultdict(lambda: 0)

    def filter_words(cs):
        for c in filter(None, cs):
            o = c.name if isinstance(c, Classification) else str(c)
            if len(o) >= 3:
                yield o

    for x, y in combinations(filter_words(classifications), 2):
        d = _edit_distance(x, y)
        similarity[x] += d
        similarity[y] += d

    return min(similarity.keys(), key=lambda k: similarity[k])


def _edit_distance(x: str, y: str) -> float:
    """
    Levenshtein edit distance between two strings (`x` & `y`)
    """
    if not isinstance(x, str) or not isinstance(y, str):
        raise TypeError("Invalid type: x=%s, y=%s", type(x), type(y))

    if x == y:
        return 0.0

    lx = len(x)
    ly = len(y)

    if lx == 0:
        return ly

    if ly == 0:
        return lx

    v0 = [0] * (ly+1)
    v1 = [0] * (ly+1)

    for i in range(ly + 1):
        v0[i] = i

    for i in range(lx):
        v1[0] = i + 1

        for j in range(ly):
            cost = 1

            if x[i] == y[j]:
                cost = 0

            v1[j + 1] = min(v1[j] + 1, v0[j + 1] + 1, v0[j] + cost)

        v0, v1 = v1, v0

    return v0[ly]


__all__ = ['guess_malware_name']
