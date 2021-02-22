from ..vocab import FAMILY_ID, TYPES, VARIANT_ID
from ._base import Classification


class Alibaba(Classification):
    pattern = rf"""^
    (({TYPES}|[^:]*)([:]|$))?
    (?&TYPES)[/]
    (?P<VEID>
        {FAMILY_ID('(?&TYPES)', r'[[:alnum:]]+')}
        {VARIANT_ID(r'[.][[:xdigit:]]{1,10}', r'[.]None', r'[.]ali[[:xdigit:]]+')}{{,3}}
    )
    $"""
