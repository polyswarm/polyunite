from typing import Iterable, Union

from collections import defaultdict
from itertools import combinations

from polyunite.parsers import Classification


def guess_malware_name(classifications: Iterable[Union[str, Classification]]) -> str:
    """
    Returns the name with the smallest total distance edit distance from `classifications`

    >>> guess_malware_name(['Zeus', 'zeus', 'zbot', 'Zeus-Trojan', 'Agent'])
    Zeus
    """
    cs = map(lambda c: c.name if isinstance(c, Classification) else c, classifications)

    # only consider words longer than 2 chars
    it = filter(lambda s: len(s) > 2, map(str, filter(None, cs)))

    # sum the square of edit distance for each word-pair
    score: defaultdict = defaultdict(lambda: 0)
    for x, y in combinations(it, 2):
        d = _edit_distance(x.lower(), y.lower())**2
        score[x] += d
        score[y] += d

    return min(score.keys(), key=lambda k: score[k])


def _edit_distance(x: str, y: str) -> float:
    """
    Levenshtein distance between `x` & `y`

    .. seealso::

        `<https://en.wikipedia.org/wiki/Levenshtein_distance#Iterative_with_two_matrix_rows>`_
            Psuedocode & description of this implementation
    """
    if not isinstance(x, str) or not isinstance(y, str):
        raise TypeError("Invalid arguments: type(x)=%s, type(y)=%s" % type(x), type(y))

    if x == y:
        return 0.0

    if len(x) == 0:
        return len(y)

    if len(y) == 0:
        return len(x)

    v0 = list(range(0, len(y) + 1))
    v1 = [0] * len(v0)

    for i in range(len(x)):
        v1[0] = i + 1
        for j in range(len(y)):
            cost = 0 if x[i] == y[j] else 1
            v1[j + 1] = min(v1[j] + 1, v0[j + 1] + 1, v0[j] + cost)
        v0, v1 = v1, v0

    return v0[len(y)]


__all__ = ['guess_malware_name']
