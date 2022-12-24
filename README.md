# Portage Lostfiles
A simple script to identify files not tracked by
[Portage](https://wiki.gentoo.org/wiki/Portage) package manager.
This package can be installed via the [GURU overlay](https://wiki.gentoo.org/wiki/Project:GURU).

## Why
Over time a large number of untracked files can accumulate,
either created manually or leftovers from uninstalled packages,
which can result in subtle bugs or misconfigurations.

## Notes
Symlinks are not reported as lost as long as the link target exists and is tracked.

Some common paths are not reported (e.g.: `/etc/group`, `/etc/machine-id`, ...),
those are defined in `IGNORED_PATHS` and `PKG_PATHS` in `lostfiles.py`.

## Usage
```bash
git clone https://github.com/gcarq/portage-lostfiles.git
cd portage-lostfiles
$ ./lostfiles.py
```

## Examples
Ignore built-in whitelist and report all files
```bash
$ ./lostfiles.py --strict
```

Override default paths
```bash
$ ./lostfiles.py -p /lib -p /lib32 -p /lib64
```

## Dependencies
* python >= 3.8
* portage >= 3, < 4