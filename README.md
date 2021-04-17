# Portage Lostfiles
A simple script to identify files not tracked by [Portage](https://wiki.gentoo.org/wiki/Portage) package manager.

## Notes
Symlinks are not reported as lost as long as the link target exists and is tracked.

Some common paths are not reported (e.g.: `/etc/group`, `/etc/machine-id`, ...). The full whitelist is defined by `WHITELIST` in `lostfiles.py`.

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
* python3.6+