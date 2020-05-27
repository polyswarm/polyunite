from collections import UserDict
import string
from typing import TYPE_CHECKING, Optional, Type

from polyunite.errors import EngineNormalizeError, MatchError, RegistryKeyError

if TYPE_CHECKING:
    from polyunite.parsers import Classification


class EngineRegistry(UserDict):
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

    def register(self, parser: 'Type[Classification]', name: 'str'):
        """Register `self` as the specialized class for handling parse requests """
        self[self._normalize(name)] = parser

    def is_heuristic(self, engine: 'str', name: 'str') -> 'Optional[bool]':
        try:
            if not engine or not name:
                return None
            return self.decode(engine, name).is_heuristic
        except (EngineNormalizeError, RegistryKeyError, MatchError):
            return None

    _translate_table = str.maketrans(
        string.ascii_uppercase,
        string.ascii_lowercase,
        string.whitespace + string.punctuation,
    )

    def _normalize(self, name: 'str'):
        """Return a 'normalized' version of this string"""
        try:
            return name.translate(self._translate_table)
        except AttributeError:
            raise EngineNormalizeError(type(name))


registry = EngineRegistry()
