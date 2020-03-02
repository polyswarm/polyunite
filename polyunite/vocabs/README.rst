MAEC Vocabularies
----------------------

This folder contains JSON files which define the MAEC vocabularies, alongside
their names and a short description.

New entries may be nested arbitrarily deeply, where each level of nesting applies it's parents label::

    {
        "virus": {
            "trojan": {
                "downloader": {
                    "__alias__": [ "dwnldr"] ,
                    "__desc__": "These are the viruses GI Joe warned you about"
                }
            }
        }
    }

This JSON would emit a regular expression as a taxonomy::

    (?P<virus>virus|(?P<trojan>trojan|(?P<downloader>downloader|dwnldr)))

This can match against both "virus", "trojan", "downloader" or "dwnldr", with
every nesting inheriting the label of it's parents and may therefore be
referenced as such::

    In [0]: re.match(r'(?P<virus>virus|...)))', 'downloader').groupdict()
    Out [0]: { 'virus': 'downloader', 'trojan': 'downloader', 'downloader': 'downloader' }
