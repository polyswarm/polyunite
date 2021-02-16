from ..vocab import FAMILY_ID, LABELS, PLATFORM, VARIANT_ID, HEURISTICS
from ._base import Classification


class FilSecLab(Classification):
    pattern = rf"""^
    ({HEURISTICS}:)?
    ({PLATFORM}|(?P<{HEURISTICS.name}>Heuri)|{LABELS})?
    (?P<VEID>
        (([.]|^)(?P<FAMILY>[A-Z][[:alpha:]]+))?
        {VARIANT_ID(r'[.][A-Z]+$', r'[.]mg', r'[.#/@][[:xdigit:]]*')}*
    )
    $"""
