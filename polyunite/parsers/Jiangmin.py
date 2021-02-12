from ..vocab import (
    FAMILY_ID,
    HEURISTICS,
    LABELS,
    OBFUSCATIONS,
    PLATFORM,
    VARIANT_ID,
)
from ._base import Classification


class Jiangmin(Classification):
    pattern = rf"""^
    (
        ([./:]|^)
        (
            {HEURISTICS}
            | Intended
            | Garbage
            | Riot
            | {LABELS}(-?(?&LABELS))?
            | {OBFUSCATIONS}
            | {PLATFORM}
        )
    )*
    (?P<VEID>
        (([./]|^){FAMILY_ID(r'[A-Z][a-z]+-[0-9]')})?
        {VARIANT_ID(r'[.][[:alnum:]]+$', '[.][A-Z][a-z]$')}{{,2}})
    $"""
