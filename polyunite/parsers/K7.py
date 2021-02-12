import regex as re

from ..vocab import LABELS
from ._base import Classification


class K7(Classification):
    pattern = rf"""^
    ([-]?{LABELS})*
    (\s*\(\s* (?P<VARIANT>[a-f0-9]+) \s*\))?
    $"""

    @property
    def name(self) -> str:
        # K7 does not work with family names
        if self.is_EICAR:
            return 'EICAR'

        return re.sub(r'^([-_\w]+) \(.*\)', r'\g<1>', self.source)
