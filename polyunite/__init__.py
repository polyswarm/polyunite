from . import errors, parsers, registry, vocab, analysis  # noqa

Registry = registry.EngineRegistry()

# NOTE: legacy interface name
parse = Registry.decode
decode = Registry.decode
is_heuristic = Registry.is_heuristic
summarize = Registry.summarize
infer_name = Registry.infer_name
analyze = Registry.analyze
