from ..vocab import FAMILY_ID, TYPES, VARIANT_ID, pattern
from ._base import Classification
from . import K7


class Alibaba(Classification):
    __av_name__ = 'Alibaba'
    __patterns__ = (
        pattern.EICAR_MATCH_ANYWHERE,
        K7.base_pattern,

        rf"""^
        (({TYPES}|[^:]*)([:]|$))?
        (?:(?&TYPES)|Package)[/]
        (?P<VEID>
            {FAMILY_ID('(?&TYPES)', r'[A-Za-z0-9][A-Za-z0-9_-]+')}
            {VARIANT_ID(r'[.][[:xdigit:]]{1,10}', r'[.]None', r'[.]ali[[:xdigit:]]+')}{{,3}}
        )
        $""",
    )
