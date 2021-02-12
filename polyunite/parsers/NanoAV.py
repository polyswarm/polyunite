from ..vocab import FAMILY_ID, LABELS, OBFUSCATIONS, PLATFORM, VARIANT_ID
from ._base import Classification


class NanoAV(Classification):
    pattern = rf"""^
    (([.-]|^)
        (
            {PLATFORM}
            | Riff
            | {LABELS}
            | {OBFUSCATIONS}
        )
    )*
    (?P<VEID>
        (
            ([./]|^)
            {FAMILY_ID(r'hidIFrame',
                            r'Iframe-scroll',
                            r'[A-Z][[:alnum:]]+',
                            r'[0-9]+[a-z]{2,}[0-9]*',
            )}
        )?
        {VARIANT_ID()}{{,2}}
    )
    $"""
