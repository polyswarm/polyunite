from ..vocab import FAMILY_ID, HEURISTICS, LABELS, PLATFORM, VARIANT_ID
from ._base import Classification


class Qihoo360(Classification):
    pattern = rf"""^
    (?i)
    {HEURISTICS}?
    (
        ([./-]|^)
        (
            Application
            | Sorter
            | AVE
            | (?<HEURISTICS>AutoVirus)
            | {PLATFORM}
            | {LABELS}
            | (QVM\d+([.]\d+)?([.][[:xdigit:]]+)?) # QVM40.1.BB16 or QVM9
        )
    )*
    (?P<VEID>
        (
            ([./]|^)
            {FAMILY_ID(r'(?-i:[A-Z][a-z]{1,2})')}?
        )?
        {VARIANT_ID()}{{,2}}
    )
    $"""
