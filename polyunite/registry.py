from typing import (
    TYPE_CHECKING,
    Callable,
    Iterable,
    Optional,
    Tuple,
    Type,
    Union,
)

import logging
import string

from polyunite.errors import (
    EngineNormalizeError,
    PolyuniteError,
    RegistryKeyError,
)

from .analysis import Analyses
from .utils import EngineName, EngineResults

if TYPE_CHECKING:
    from polyunite.parsers import Classification

logger = logging.getLogger(__name__)

_ENGINE_NAME_XLATE = str.maketrans(
    string.ascii_uppercase,
    string.ascii_lowercase,
    string.whitespace + string.punctuation,
)


class EngineRegistry:
    _registry = dict()

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
            logger.debug('Error parsing %s using %s: %s', name, engine, e)
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
        registration = cls._normalize(name)
        cls._registry[registration] = parser
        return registration

    def each(self, results: EngineResults) -> Iterable[Tuple[EngineName, 'Classification']]:
        """
        Return an iterator of engines with their family name decoded into a classification
        """
        for engine, family in results.items():
            if isinstance(family, (str, list)):
                try:
                    clf = self.decode(engine, family)
                    yield clf.registration, clf
                except PolyuniteError as e:
                    logger.info(e)
                    continue

    def analyze(self, results: EngineResults, **kwargs):
        return Analyses(self.each(results), **kwargs)

    def summarize(
        self,
        results: EngineResults,
        key: Callable[['Classification'], Union[Iterable[str], str]] = None,
        top_k: int = None
    ):
        """
        Return an iterator of unique applications of ``key`` to the decoded malware family of each
        engine in ``results``. ``top_k`` selects only the most common k applications of key.
        """
        return self.analyze(results).summarize(key=key, top_k=top_k)

    def infer_name(self, results: EngineResults, normalize=True, **kwargs):
        """
        Returns the name with the smallest total distance edit distance from `classifications`

        >>> registry.infer_name({'Ikarus': 'Zeus', 'Rising': 'zeus', 'Qihoo360': 'zbot',
                                 'Virusdie': 'Zeus-Trojan', 'QuickHeal': 'Agent'})
        Zeus
        """
        if normalize and 'weights' in kwargs:
            kwargs['weights'] = self.normalize_dict(kwargs['weights'])

        return self.analyze(results).infer_name(**kwargs)

    @staticmethod
    def _normalize(name: 'str'):
        """Return a 'normalized' version of this string"""
        try:
            return name.translate(_ENGINE_NAME_XLATE)
        except AttributeError as e:
            raise EngineNormalizeError(type(name)) from e

    def normalize_dict(self, d, raise_missing=False):
        """Return a dictionary with normalized keys"""
        r = dict()

        for k, v in d.items():
            n = self._normalize(k)

            if n in self:
                r[n] = v
            elif raise_missing:
                raise RegistryKeyError(k)
            else:
                continue

        return r
