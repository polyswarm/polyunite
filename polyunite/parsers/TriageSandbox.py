from ._base import Classification


class TriageSandbox(Classification):
    pattern = rf"""^(.+)$"""
