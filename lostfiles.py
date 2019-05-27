#!/usr/bin/env python3
import argparse
import itertools
import os
from glob import glob
from pathlib import Path
from typing import List, Set

PORTAGE_DB = '/var/db/pkg'

DIRS_TO_CHECK = {
    '/bin',
    '/etc',
    '/lib',
    '/lib32',
    '/lib64',
    '/opt',
    '/sbin',
    '/srv',
    '/usr',
    '/var',
}

# Every path defined in whitelist is ignored
WHITELIST = {
    '/etc/.etckeeper',
    '/etc/.git',
    '/etc/.gitignore',
    '/etc/.pwd.lock',
    '/etc/.updated',
    '/etc/crypttab',
    '/etc/fstab',
    '/etc/gconf/gconf.xml.defaults',
    '/etc/group',
    '/etc/group-',
    '/etc/gshadow',
    '/etc/gshadow-',
    '/etc/hostname',
    '/etc/ld.so.cache',
    '/etc/ld.so.conf',
    '/etc/locale.conf',
    '/etc/localtime',
    '/etc/machine-id',
    '/etc/passwd',
    '/etc/passwd-',
    '/etc/portage',
    '/etc/resolv.conf',
    '/etc/shadow',
    '/etc/shadow-',
    '/etc/timezone',
    '/etc/udev/hwdb.bin',
    '/etc/vconsole.conf',
    '/lib/modules',
    '/usr/lib/ccache',
    '/usr/portage',
    '/usr/sbin/fix_libtool_files.sh',
    '/usr/share/applications/mimeinfo.cache',
    '/usr/share/fonts/.uuid',
    '/usr/share/info/dir',
    '/usr/share/mime',
    '/var/.updated',
    '/var/cache',
    '/var/db',
    '/var/lib/gentoo/news',
    '/var/lib/layman',
    '/var/lib/portage',
    '/var/lib/sddm/.cache',
    '/var/lib/systemd',
    '/var/lock',
    '/var/log',
    '/var/run',
    '/var/spool',
    '/var/tmp',
    *glob('/usr/share/.mono/*/Trust'),
    *glob('/usr/share/fonts/**/.uuid', recursive=True),
    *glob('/usr/share/fonts/*/*.dir'),
    *glob('/usr/share/fonts/*/*.scale'),
    *glob('/usr/src/linux*'),  # Ignore kernel source directories
}


def main(args: argparse.Namespace) -> None:
    files = collect_tracked_files()
    for dirname in DIRS_TO_CHECK:
        for dirpath, dirnames, filenames in os.walk(dirname, topdown=True):
            if not args.strict:
                # Modify dirnames in-place to apply whitelist filter
                dirnames[:] = [d for d in dirnames
                               if os.path.join(dirpath, d) not in WHITELIST]

            for name in filenames:
                if not args.strict and name == '.keep':
                    continue

                filepath = os.path.join(dirpath, name)
                if not args.strict and filepath in WHITELIST:
                    continue

                if filepath not in files \
                        and os.path.realpath(filepath) not in files:
                    print(filepath)


def resolve_symlinks(*paths) -> Set[str]:
    return set(itertools.chain.from_iterable(
        (path, os.path.realpath(path)) for path in paths))


def normalize_filenames(files: List[str]) -> Set[str]:
    """Normalizes a list of CONTENT and returns a set of absolute file paths"""
    normalized = set()
    for f in files:
        ctype, rem = f.rstrip().split(' ', maxsplit=1)
        if ctype == 'dir':
            # format: dir <path>
            normalized.update(resolve_symlinks(rem))

        elif ctype == 'obj':
            # format: obj <path> <md5sum> <unixtime>
            parts = rem.rsplit(' ', maxsplit=2)
            assert len(parts) == 3, 'unknown obj syntax definition for: %s' % f
            normalized.update(resolve_symlinks(parts[0]))

        elif ctype == 'sym':
            # format: sym <source> -> <target> <unixtime>
            parts = rem.split(' ')
            assert len(parts) == 4, 'unknown obj syntax definition for: %s' % f
            sym_origin = parts[0]
            if parts[2].startswith('/'):
                sym_target = parts[2]
            else:
                sym_target = os.path.join(
                    os.path.dirname(sym_origin), parts[2])
            normalized.update(resolve_symlinks(sym_origin, sym_target))

        else:
            raise AssertionError('Unknown content type: %s' % ctype)

    return normalized


def collect_tracked_files() -> Set[str]:
    """Returns a set of files tracked by portage"""
    files = set()
    for filename in Path(PORTAGE_DB).glob('**/CONTENTS'):
        with open(str(filename), mode='r') as fp:
            files.update(normalize_filenames(fp.readlines()))

    if not files:
        raise AssertionError('No tracked files found. This is probably a bug!')
    return files


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument(
        '--strict', help='run in strict mode', action='store_true')
    main(parser.parse_args())
