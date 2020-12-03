from typing import (
    TYPE_CHECKING,
    Callable,
    Iterable,
    Mapping,
    Optional,
    Tuple,
    Type,
    Union,
)

from collections import Counter, UserDict, defaultdict
from itertools import combinations
import string

from polyunite.errors import EngineNormalizeError, MatchError, RegistryKeyError
from polyunite.utils import edit_distance

if TYPE_CHECKING:
    from polyunite.parsers import Classification

EngineName = str
EngineResults = Mapping[EngineName, str]

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
        """
        Parse `name` with a specialized parsing class identified by `engine`, returning `None` if an
        error is encountered
        """
        try:
            if not engine or not name:
                return None
            return self.decode(engine, name)
        except (EngineNormalizeError, RegistryKeyError, MatchError):
            return None

    def is_heuristic(self, engine: 'str', name: 'str') -> 'Optional[bool]':
        """
        Check if a malware family ``name`` produced by ``engine`` was heuristic
        """
        return self.try_decode(engine, name).is_heuristic

    def register(self, parser: 'Type[Classification]', name: 'str'):
        """Register `self` as the specialized class for handling parse requests """
        self[self._normalize(name)] = parser

    def each(self, results: EngineResults) -> Iterable[Tuple[EngineName, 'Classification']]:
        """
        Return an iterator of engines with their family name decoded into a classification
        """
        for engine, family in results.items():
            if isinstance(family, str):
                try:
                    yield engine, self.decode(engine, family)
                except (EngineNormalizeError, RegistryKeyError, MatchError):
                    continue

    def summarize(
        self,
        results: EngineResults,
        key: Callable[['Classification'], Union[Iterable[str], str]] = None,
        top_k: int = None,
        min_density: float = 0.0,
    ):
        """
        Return an iterator of unique applications of ``key`` to the decoded malware family of each
        engine in ``results``. ``top_k`` selects only the most common k applications of key,
        ``min_density`` excludes any whose frequency divided by the most common element's frequency
        is below this value.
        """
        ctr: Counter = Counter()

        for _, clf in self.each(results):
            try:
                r = key(clf)
                if isinstance(r, str):
                    ctr[r] += 1
                else:
                    ctr.update(r)
            except (AttributeError, LookupError, TypeError):
                continue

        (top, top_count), *rest = ctr.most_common(top_k)

        yield top

        for elt, count in rest:
            if count / top_count > min_density:
                yield elt

    def infer_name(self, families: Mapping[str, str]):
        """
        Returns the name with the smallest total distance edit distance from `classifications`

        >>> registry.infer_name({'Ikarus': 'Zeus', 'Rising': 'zeus', 'Qihoo360': 'zbot',
                                  'Virusdie': 'Zeus-Trojan', 'QuickHeal': 'Agent'})
        Zeus
        """
        return self._weighted_name_inference((
            (clf.name, self.weights.get(engine, 1.0))
            for engine, clf in self.each(families)
        ))

    def _weighted_name_inference(self, names: Iterable[Tuple[str, float]]) -> str:
        # only consider words longer than 2 chars
        # sum the square of edit distance for each word-pair
        iterator = ((n, w) for n, w in names if len(n) > 2 or w == 0)
        score: defaultdict = defaultdict(lambda: 0)

        for (x, xw), (y, yw) in combinations(iterator, 2):
            weight_ratio = xw / yw
            d = weight_ratio * edit_distance(x.lower(), y.lower())
            score[x] += d
            score[y] += d

        return max(score.keys(), key=lambda k: score[k])

    @staticmethod
    def _normalize(name: 'str'):
        """Return a 'normalized' version of this string"""
        try:
            return name.translate(_ENGINE_NAME_XLATE)
        except AttributeError as e:
            raise EngineNormalizeError(type(name)) from e


registry = EngineRegistry()
