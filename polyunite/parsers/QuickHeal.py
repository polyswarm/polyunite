from ..vocab import FAMILY_ID, LABELS, PLATFORM, VARIANT_ID
from ._base import Classification


class QuickHeal(Classification):
    pattern = rf"""^
    (
        ([./]|^)
        ({PLATFORM}|{LABELS}(?&LABELS)?|Cmd|PIF|alware)
    )*
    (?P<VEID>
        (
            (?![.]([A-Z][[:xdigit:]]+\b|GEN[0-9]+))
            ([./]|^)
            {FAMILY_ID(
                r'(?# e.x `Trojan.2345Cn` )'
                r'[0-9]+[A-Z][a-z]+',

                r'(?# e.x `Trojan.Nuj` )'
                r'[A-Z][a-z]{2}',
            )}
        )?
        {VARIANT_ID(
            r'(?# TODO Add groups to identify each of these suffix attrs )'
            r'(PMF|B|AD|RI|FC|CS|VMF|MF)',

            r'(?# e.x `Android.Hiddad.A2d3d` )'
            r'[.]A[a-f0-9]+$',

            r'(?# e.x `O97.Madeba.3874`)'
            r'[.][0-9]+$',

            r'(?# e.x `Ransomware.WannaCry.IRG1`)'
            r'[.][A-Z][0-9A-F]{3,}',

            r'[.]HTML[.][A-Z]',
            r'[-][A-Z]',
            r'[.][A-Z][0-9A-F]{3,}',
            r'[.][A-Z]{1,3}[0-9]{1,2}',
            )}{{,2}}
    )?
    $"""
