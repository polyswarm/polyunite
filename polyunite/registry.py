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

from collections import Counter
import logging
from rapidfuzz import process
import string

from polyunite.errors import (
    EngineNormalizeError,
    PolyuniteError,
    RegistryKeyError,
)

from .utils import flatmap

if TYPE_CHECKING:
    from polyunite.parsers import Classification

log = logging.getLogger('polyunite')

EngineName = str
EngineResults = Mapping[EngineName, str]

_ENGINE_NAME_XLATE = str.maketrans(
    string.ascii_uppercase,
    string.ascii_lowercase,
    string.whitespace + string.punctuation,
)

from .vocab import (
    ARCHIVES,
    HEURISTICS,
    LABELS,
    LANGS,
    MACROS,
    OBFUSCATIONS,
    OSES,
)


class EngineRegistry:
    _registry = dict()

    def __init__(
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
        self.weights = {self._normalize(k): v for k, v in weights.items()}
        self.name_weights = name_weights
        self.taxon_weight = taxon_weight
        super().__init__()

    @classmethod
    def __contains__(cls, engine):
        return cls._registry.__contains__(cls._normalize(engine))

    @classmethod
    def __getitem__(cls, engine):
        """Lookup the engine-specialized parser"""
        try:
            return cls._registry.__getitem__(cls._normalize(engine))
        except KeyError:
            raise RegistryKeyError(engine)

    def decode(self, engine: 'str', name: 'str') -> 'Classification':
        """Parse `name` with a specialized parsing class identified by `engine`

        :raises polyunite.errors.RegistryKeyError: No engine found with this name
        :raises polyunite.errors.EngineNormalizeError: Couldn't normalize engine name
        """
        try:
            return self[engine].from_string(name)
        except PolyuniteError as e:
            log.debug('Error parsing %s using %s: %s', name, engine, e)
            raise

    def try_decode(self, engine: 'str', name: 'str') -> 'Optional[Classification]':
        """
        Parse `name` with a specialized parsing class identified by `engine`, returning `None` if an
        error is encountered
        """
        try:
            if not engine or not name:
                return None
            return self.decode(engine, name)
        except PolyuniteError:
            return None

    def is_heuristic(self, engine: 'str', name: 'str') -> 'Optional[bool]':
        """
        Check if a malware family ``name`` produced by ``engine`` was heuristic
        """
        try:
            return self.decode(engine, name).is_heuristic
        except PolyuniteError:
            return False

    @classmethod
    def register(cls, parser: 'Type[Classification]', name: 'str'):
        """Register `self` as the specialized class for handling parse requests """
        cls._registry[cls._normalize(name)] = parser

    def each(self, results: EngineResults) -> Iterable[Tuple[EngineName, 'Classification']]:
        """
        Return an iterator of engines with their family name decoded into a classification
        """
        for engine, family in results.items():
            if isinstance(family, str):
                try:
                    clf = self.decode(engine, family)
                    yield clf.registration_name(), clf
                except PolyuniteError:
                    continue

    def summarize(
        self,
        results: EngineResults,
        key: Callable[['Classification'], Union[Iterable[str], str]] = None,
        top_k: int = None,
    ):
        """
        Return an iterator of unique applications of ``key`` to the decoded malware family of each
        engine in ``results``. ``top_k`` selects only the most common k applications of key.
        """
        each = tuple(p for _, p in self.each(results))

        if not each:
            return []

        ctr = Counter(sorted(filter(None, flatmap(key, each))))
        return [elt for elt, _ in ctr.most_common(top_k)]

    def infer_name(self, families: Mapping[str, str]):
        """
        Returns the name with the smallest total distance edit distance from `classifications`

        >>> registry.infer_name({'Ikarus': 'Zeus', 'Rising': 'zeus', 'Qihoo360': 'zbot',
                                  'Virusdie': 'Zeus-Trojan', 'QuickHeal': 'Agent'})
        Zeus
        """
        if not families:
            return

        name_weights = self.name_weights.items()

        def weighted_names(elts):
            for engine, clf in elts:
                weight = 1

                name = clf.family

                if name is None:
                    name = clf.taxon
                    weight *= self.taxon_weight

                # Only consider strings longer than 2 chars
                if isinstance(name, str) and len(name) > 2:
                    weight *= self.weights.get(engine, 1.0)

                    for predicate, adjustment in name_weights:
                        if predicate(name):
                            weight = weight * adjustment
                            break

                    if weight >= 0:
                        yield name, weight

        return self._weighted_name_inference(weighted_names(self.each(families)))

    def _weighted_name_inference(self, names: Iterable[Tuple[str, float]]) -> str:
        items = tuple((n, w) for n, w in names)
        names = tuple(n for n, w in items)
        weights = dict(items)

        def edit_distance(name):
            matches = process.extract(name, names, score_cutoff=0.25)
            return sum(score * weights[name] for _, score, _ in matches)

        if weights:
            return max(names, key=edit_distance)

    @staticmethod
    def _normalize(name: 'str'):
        """Return a 'normalized' version of this string"""
        try:
            return name.translate(_ENGINE_NAME_XLATE)
        except AttributeError as e:
            raise EngineNormalizeError(type(name)) from e
