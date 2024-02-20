from ..vocab import (
    FAMILY_ID,
    HEURISTICS,
    LABELS,
    PLATFORM,
    VARIANT_ID,
    pattern,
)
from ._base import Classification


class FilSecLab(Classification):
    __av_name__ = 'FilSecLab'
    __patterns__ = (
        pattern.EICAR_MATCH_ANYWHERE,
    rf"""^
    ({HEURISTICS}:)?
    ({PLATFORM}|{LABELS})?
    (?P<VEID>
        (([.]|^)(?P<FAMILY>[A-Z][[:alpha:]]+))?
        {VARIANT_ID(r'[.][A-Z]+$', r'[.]mg', r'[.#/@][[:xdigit:]]*')}*
    )
    $""",
    )
