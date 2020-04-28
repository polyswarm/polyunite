class EngineNormalizeError(TypeError):
    """This value couldn't be normalized as an engine's name, check it's type"""


class DecodeError(ValueError):
    """A generic error occurred decoding an engine's classification"""


class EngineKeyError(DecodeError):
    """No decoder has been created for this engine"""


class MatchError(DecodeError):
    """Invalid classification string"""
