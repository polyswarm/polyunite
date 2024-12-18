from ..vocab import FAMILY_ID, HEURISTICS, LABELS, PLATFORM, VARIANT_ID
from ._base import Classification


class Qihoo360(Classification):
    pattern = rf"""^
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
            {FAMILY_ID(r'(?<=[a-z]+[.])[a-z]{4,}', r'qexvmI')}?
        )?
        {VARIANT_ID(r'[.][A-Z]{2}[0-9]?', r'[@][[:alnum:]]+')}{{,3}}
    )
    $"""
