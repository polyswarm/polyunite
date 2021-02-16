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
            {PLATFORM}
            | Intended
            | Garbage
            | Riot
            | {LABELS}(-?(?&LABELS))?
        )
    )*
    (?P<VEID>
        (
            ([./]|^)
            (
                {FAMILY_ID(r'[A-Z][a-z]+-[0-9]')}
                | [A-Z][a-z]{{1,2}}(?=[.])
            )
        )?
        {VARIANT_ID()}{{,2}}
    )?
    $"""
