from typing import ClassVar, Dict, Optional

from polyunite.errors import (
    PolyuniteDecodeError,
    PolyuniteEngineLookupError,
    PolyuniteEngineMapError,
)


class EngineRegistry:
    registry: ClassVar[Mapping] = {}

    def map_to_decoder(self, engine: str, cls):
        """Register cls as the specialized class for handling "engine" engines. """
        if engine and isinstance(engine, str):
            self.registry[engine.lower()] = cls
        else:
            raise PolyuniteEngineMapError

    def __getitem__(self, engine: str):
        try:
            return self.registry[engine.lower()]
        except KeyError:
            raise PolyuniteEngineLookupError

    def __call__(self, engine: str, classification: str):
        """Create an engineparts instance for engine 'engine' from 'classification'.

        Creates an instance by creating a specialized class for parsing and representing the
        specified engine's classification by combining the factory base_class with a specialized
        class from the registry
        """
        return self[engine](classification)

    def is_heuristic(self, engine: str, classification: str):
        try:
            decoding = self(engine, classification).is_heuristic
            return decoding.is_heuristic
        except (PolyuniteDecodeError, PolyuniteEngineLookupError):
            return None


registry = EngineRegistry()
