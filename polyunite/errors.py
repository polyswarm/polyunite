class EngineNormalizeError(TypeError):
    """This value couldn't be normalized as an engine's name, check it's type"""


class ParseError(ValueError):
    """A generic error occurred decoding an engine's classification"""


class EngineKeyError(ParseError):
    """No parser has been created for this engine"""


class MatchError(ParseError):
    """Invalid classification string"""
