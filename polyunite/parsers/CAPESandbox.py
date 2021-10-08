from ..vocab import FAMILY_ID
from ._base import Classification


class CapeSandbox(Classification):
    pattern = rf"""^
    (family[:./-]?)?
    (?P<VEID>
        {FAMILY_ID(r'[[:alnum:]]+')}
    )$"""
