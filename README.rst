=========
polyunite
=========

polyunite parses a antimalware vendor's classification strings into a unified format with logical interpolation of other features.


Supported:
--------

- Alibaba
- ClamAV
- DrWeb
- Ikarus
- Jiangmin
- K7
- Lionic
- NanoAV
- Qihoo360
- QuickHeal
- Rising
- Virusdie


Features
--------

To view a sample of how each ``polyunite`` breaks down each classification string, run::

  python tests/colorize.py

Each color corresponds to a different feature (such as "family", "label", "is heuristic", ...)
