from ..vocab import FAMILY_ID, HEURISTICS, LABELS, PLATFORM, VARIANT_ID
from ._base import Classification


class FilSecLab(Classification):
    pattern = rf"""^
    ({HEURISTICS}:)?
    ({PLATFORM}|{LABELS})?
    (?P<VEID>
        (([.]|^)(?P<FAMILY>[A-Z][[:alpha:]]+))?
        {VARIANT_ID(r'[.][A-Z]+$', r'[.]mg', r'[.#/@][[:xdigit:]]*')}*
    )
    $"""
