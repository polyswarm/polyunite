from ..vocab import FAMILY_ID, LABELS, PLATFORM, VARIANT_ID
from ._base import Classification


class Ikarus(Classification):
    pattern = rf"""^
    (
        ([.:-]|^)
        (
            {LABELS}(-?(?&LABELS))?
            | (BehavesLike)?{PLATFORM}
            | AIT
            | ALS
            | BDC
            | (Client|Server)-[[:alpha:]]+
            | Conduit
            | Damaged
            | DongleHack
            | Fraud
            | Fake
            | FTP
            | MalwareScope
            | Optional
            | Patch
            | PCK
            | SPR
            | ToolKit
            | Troja
            | X2000M
        )
    )*
    (?P<VEID>
      (
          (^|[.:])
          {FAMILY_ID(
            r'(?P<HEURISTICS>NewHeur_[a-zA-Z0-9_-]+)',
            r'^[A-Z][a-zA-Z0-9_-]+$',
            r'PDF-[[:alnum:]]+',
            r'Equation.Eternalblue',
           )}
       )?
       {VARIANT_ID(
                r'[.]SuspectCRC',
                r'20[0-9]{2}-[0-9]{1,6}',
                r'[-][A-Z]',
                r'[-][0-9]+$',
                r'[.](?|Dm|Ra)',
                r'[.]gen[0-9]x',
                r'[.][A-Z]{2,3}',
                r'[.][A-Z][a-z]{2}',
                r'[.][A-Z]{1,2}[0-9]*',
                r'[.][A-Z][a-z0-9]$',
                r'[:][[:alpha:]]+',
       )}{{,3}}
       ([.]{PLATFORM})?
    )?
    $"""
