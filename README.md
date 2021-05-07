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

Append files or directories to whitelist
```bash
$ ./lostfiles.py -e /etc/awstats -e /etc/drbd.d/*.res
```

Verbose output with size and time of files and print sizes in human-readable format (e.g., 1K 234M 2G)
```bash
$ ./lostfiles.py --verbose --human
```

Verbose output with size and age of files in days
```bash
$ ./lostfiles.py --verbose --age
```

Append files or directories to whitelist from file
```bash
$ ./lostfiles.py -E /etc/listfiles.conf
```

Ask to remove each file
```bash
$ ./lostfiles.py --verbose --ask
```

## Dependencies
* python3.6+
* psutil