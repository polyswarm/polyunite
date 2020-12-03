from . import errors, parsers, vocab  # noqa
from .registry import registry  # noqa

# NOTE: legacy interface name
parse = registry.decode
decode = registry.decode
is_heuristic = registry.is_heuristic
summarize = registry.summarize
infer_name = registry.infer_name
