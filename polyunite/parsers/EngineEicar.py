from ._base import Classification


class EngineEicar(Classification):
    pattern = rf"""^(.+)$"""
