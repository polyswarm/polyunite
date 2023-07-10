from ._base import Classification


class FamilyTag(Classification):
    pattern = rf"""^(.+)$"""
