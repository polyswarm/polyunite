from ..vocab import FAMILY_ID, LABELS, PLATFORM, VARIANT_ID
from ._base import Classification


class Alibaba(Classification):
    pattern = rf"""^
    (({PLATFORM}|{LABELS}([-]?(?&LABELS))?|[^:]*)([:]|$))?
    {PLATFORM}[/]
    (?P<VEID>
        {FAMILY_ID('(?&LABELS)', r'[[:alnum:]]+')}
        {VARIANT_ID(r'[.][[:xdigit:]]{1,10}', r'[.]None', r'[.]ali[[:xdigit:]]+')}{{,3}}
    )
    $"""
