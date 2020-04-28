from . import errors, parsers, vocab
from .registry import EngineRegistry

# NOTE: legacy interface name
parse = EngineRegistry.parse_with

__all__ = ['parsers', 'vocab', 'errors', 'registry', 'parse']
