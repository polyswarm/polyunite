class PolyuniteError(Exception):
    """Base error class for Polyunite

    Args:
        message (str): specific error message
        root_exception (Exception): Exception instance of root exception
    """
    def __init__(self, message):
        self.message = message

    def __str__(self):
        return "{0.message}.".format(self)


class EngineNormalizeError(PolyuniteError):
    """A value of this type could not be normalized into a registry name"""
    def __init__(self, name):
        super().__init__(f"{name} cannot be normalized into an engine registry key")


class MatchError(PolyuniteError):
    """An exception was raised by an while decoding a malware name"""
    def __init__(self, name, source='malware'):
        super().__init__(f"Could not decode {name} as a {source} family")


class RegistryKeyError(PolyuniteError):
    """No name decoder was found with this name"""
    def __init__(self, engine):
        super().__init__(f"Could not normalize {engine} as an engine name.")


# For backwards compatibility
EngineKeyError = RegistryKeyError
