import string
from typing import TYPE_CHECKING, ClassVar, Dict, Type

from polyunite.errors import EngineKeyError, EngineNormalizeError

if TYPE_CHECKING:
    from polyunite.decoders import ClassificationDecoder


class EngineRegistry:
    registry: 'ClassVar[Dict[str, type]]' = {}

    @classmethod
    def decode(cls, engine: 'str', classification: 'str') -> 'ClassificationDecoder':
        """Create an engineparts instance for engine 'engine' from 'classification'.

        Creates an instance by creating a specialized class for parsing and representing the
        specified engine's classification by combining the factory base_class with a specialized
        class from the registry
        """
        return cls.map_to_decoder(engine)(classification)

    @classmethod
    def create_decoder(cls, decoder: 'Type[ClassificationDecoder]', name: 'str'):
        """Register cls as the specialized class for handling "engine" engines. """
        cls.registry[cls._normalize(name)] = decoder

    @classmethod
    def map_to_decoder(cls, engine: 'str'):
        """Lookup the engine-specialized decoder"""
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


decode = EngineRegistry.decode
