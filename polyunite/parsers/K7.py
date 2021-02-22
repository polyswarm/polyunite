import regex as re

from ..vocab import TYPES
from ._base import Classification


class K7(Classification):
    pattern = rf"""^
    {TYPES}\s*
    (\s*\(\s* (?P<VARIANT>[a-f0-9]+) \s*\))?
    $"""

    @property
    def name(self) -> str:
        # K7 does not work with family names
        if self.is_EICAR:
            return 'EICAR'

        if 'TYPES' in self:
            return self['TYPES']
