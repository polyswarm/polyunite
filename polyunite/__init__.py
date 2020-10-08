from . import errors, parsers, vocab, analysis
from .registry import registry

# NOTE: legacy interface name
parse = registry.decode
decode = registry.decode
is_heuristic = registry.is_heuristic
guess_name = analysis.guess_malware_name

__all__ = ['parsers', 'vocab', 'errors', 'registry', 'parse', 'decode', 'is_heuristic', 'guess_name']
