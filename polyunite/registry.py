from collections import UserDict
import string
from typing import TYPE_CHECKING, Optional, Type, Iterable, Tuple, Mapping

from collections import defaultdict
from itertools import combinations

from polyunite.errors import EngineNormalizeError, MatchError, RegistryKeyError
from polyunite.utils import edit_distance

if TYPE_CHECKING:
    from polyunite.parsers import Classification

_ENGINE_NAME_XLATE = str.maketrans(
    string.ascii_uppercase,
    string.ascii_lowercase,
    string.whitespace + string.punctuation,
)


class EngineRegistry(UserDict):
    def __init__(self, *, weights={}):
        self.weights = {}

        for engine, weight in weights.items():
            try:
                self.weights[self._normalize(engine)] = weight
            except EngineNormalizeError:
                continue

        super().__init__()

    def __contains__(self, engine):
        return super().__contains__(self._normalize(engine))

    def __getitem__(self, engine):
        """Lookup the engine-specialized parser"""
        try:
            return super().__getitem__(self._normalize(engine))
        except KeyError:
            raise RegistryKeyError(engine)

    def decode(self, engine: 'str', name: 'str') -> 'Classification':
        """Parse `name` with a specialized parsing class identified by `engine`

        :raises polyunite.errors.RegistryKeyError: No engine found with this name
        :raises polyunite.errors.EngineNormalizeError: Couldn't normalize engine name
        """
        return self[engine].from_string(name)

    def try_decode(self, engine: 'str', name: 'str') -> 'Optional[Classification]':
        try:
            if not engine or not name:
                return None
            return self.decode(engine, name)
        except (EngineNormalizeError, RegistryKeyError, MatchError):
            return None

    def is_heuristic(self, engine: 'str', name: 'str') -> 'Optional[bool]':
        return self.try_decode(engine, name).is_heuristic

    def register(self, parser: 'Type[Classification]', name: 'str'):
        """Register `self` as the specialized class for handling parse requests """
        self[self._normalize(name)] = parser

    def each(self, results):
        for engine, family in results.items():
            if isinstance(family, str):
                try:
                    yield engine, self.decode(engine, family)
                except (EngineNormalizeError, RegistryKeyError, MatchError):
                    continue

    def infer_name(self, families: Mapping[str, str]):
        """
        Returns the name with the smallest total distance edit distance from `classifications`

        >>> registry.infer_name({'Ikarus': 'Zeus', 'Rising': 'zeus', 'Qihoo360': 'zbot',
                                  'Virusdie': 'Zeus-Trojan', 'QuickHeal': 'Agent'})
        Zeus
        """
        return self._weighted_name_inference(((clf.name, self.weights.get(engine, 1.0))
                                              for engine, clf in self.each(families)))

    def _weighted_name_inference(self, names: Iterable[Tuple[str, float]]) -> str:
        # only consider words longer than 2 chars
        # sum the square of edit distance for each word-pair
        score: defaultdict = defaultdict(lambda: 0)

        for (x, xw), (y, yw) in combinations(((n, w) for n, w in names if len(n) > 2), 2):
            weight_ratio = xw / yw
            d = (edit_distance(x.lower(), y.lower())**2) * weight_ratio
            score[x] += d
            score[y] += d

        return min(score.keys(), key=lambda k: score[k])

    @staticmethod
    def _normalize(name: 'str'):
        """Return a 'normalized' version of this string"""
        try:
            return name.translate(_ENGINE_NAME_XLATE)
        except AttributeError as e:
            raise EngineNormalizeError(type(name)) from e


registry = EngineRegistry()
