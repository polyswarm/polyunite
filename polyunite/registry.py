from typing import ClassVar, Dict, Optional

class EngineRegistry:
    registry: ClassVar[Mapping] = {}

    def map_to_decoder(self, name: str, cls):
        """Register cls as the specialized class for handling "name" engines. """
        self.registry[name.lower()] = cls

    def __getitem__(self, name: str):
        return self.registry[name.lower()]

    def __call__(self, name: str, classification: str):
        """Create an engineparts instance for engine 'name' from 'classification'.

        Creates an instance by creating a specialized class for parsing and representing the
        specified engine's classification by combining the factory base_class with a specialized
        class from the registry
        """
        return self[name](classification)


registry = EngineRegistry()
