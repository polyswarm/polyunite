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
            ([./]|^)

            # e.x don't select names from `Trojan.Miner.S17531` &
            # `Android.Agent.Abd1` & `Trojan.AndroidOS.GEN26762`
            (?!S[0-9]+$|GEN[0-9]+$|A[a-f0-9]+$)

            {FAMILY_ID(
                r'(?# e.x `Trojan.2345Cn` )'
                r'[0-9]+[A-Z][a-z]+?',
                r'(?# e.x `Trojan.Nuj` )'
                r'[A-Z][a-z]{2}',
                standard=[
                    r'[0-9a-z]{1,2}[A-Z][a-zA-Z]{2,}?',
                    r'[A-Z][a-zA-Z0-9_]{3,}?',
                ]
            )}
        )?

        # TODO Add groups to identify each of these suffix attrs
        (PMF|B|AD|RI|FC|CS|VMF|MF)?

        {VARIANT_ID(
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
