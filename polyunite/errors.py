class EngineNormalizeError(TypeError):
    """A value of this type could not be normalized into a registry name"""


class MatchError(ValueError):
    """An exception was raised by an while decoding a malware name"""


class RegistryKeyError(KeyError):
    """No name decoder was found with this name"""


# For backwards compatibility
EngineKeyError = RegistryKeyError
