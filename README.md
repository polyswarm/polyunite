# `polyunite`

`polyunite` parses anti-malware classification strings into their constitutent
parts (family, variant, labels, OS, ...), as well as useful metadata like:

- Is the family shown in this classification an internal name for generic or heuristic scan results?
- What packer was used with this malware?
- Is this a detection of non- or para-malware such as a security assessment ("hack") tool, PUP or software crack?

## Features

You can view a report showing `polyunite`'s parsing of a sampling of each engine's classification strings

```console
$ make report
```

Output is color-coded by malware family feature (e.g `label`, `family name`, `variant id`, etc.)

[Report Output](images/report.png)


### Debugging and Testing

You can show the underlying regular expressions built for each engine with:

```console
$ make patterns-report
```

If you've added a new engine or made breaking changes to an existing engine,
you'll need to rebuild the fixture archive (which you should make sure is
correct before pushing):

```console
$ make result-fixtures
```

## Supported Engines

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
- URLHaus
