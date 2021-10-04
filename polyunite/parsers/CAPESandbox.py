from ..vocab import FAMILY_ID, TYPES, VARIANT_ID
from ._base import Classification

class CapeSandbox(Classification):
    pattern = rf"""^(?:family[:./-]?)?(?P<VEID>{FAMILY_ID('(?&TYPES)', r'[[:alnum:]]+')})$"""
