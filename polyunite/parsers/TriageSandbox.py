from ..vocab import FAMILY_ID
from ._base import Classification


class TriageSandbox(Classification):
    pattern = rf"""^
    (family[:./-]?)?
    (?P<VEID>
        {FAMILY_ID(r'[[:alnum:]]+')}
    )$"""
