import string
from typing import TYPE_CHECKING, ClassVar, Dict, Type

from polyunite.errors import EngineKeyError, EngineNormalizeError

if TYPE_CHECKING:
    from polyunite.parsers import ClassificationParser


class EngineRegistry:
    registry: 'ClassVar[Dict[str, type]]' = {}

    @classmethod
    def parse(cls, engine: 'str', classification: 'str') -> 'ClassificationParser':
        """Parse `classification` with a specialized parsing class identified by `engine`

        :raises polyunite.errors.ParseError: An error occurred decoding the message
        :raises polyunite.errors.EngineKeyError: No engine found with this name
        """
        return cls.map_to_parser(engine)(classification)

    @classmethod
    def create_parser(cls, parser: 'Type[ClassificationParser]', name: 'str'):
        """Register `cls` as the specialized class for handling parse requests """
        cls.registry[cls._normalize(name)] = parser

    @classmethod
    def map_to_parser(cls, engine: 'str'):
        """Lookup the engine-specialized parser"""
        try:
            return cls.registry[cls._normalize(engine)]
        except KeyError:
            raise EngineKeyError

    _translate_table = str.maketrans(
        string.ascii_uppercase,
        string.ascii_lowercase,
        string.whitespace + string.punctuation,
    )

    @classmethod
    def _normalize(cls, name: 'str'):
        """Return a 'normalized' version of this string"""
        try:
            return name.translate(cls._translate_table)
        except AttributeError:
            raise EngineNormalizeError


parse = EngineRegistry.parse
