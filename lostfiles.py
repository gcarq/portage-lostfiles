#!/usr/bin/env python3
import argparse
import itertools
import os
from glob import glob
from pathlib import Path
from typing import List, Set

VERSION = 0.1
PORTAGE_DB = '/var/db/pkg'
DIRS_TO_CHECK = {
    '/bin',
    '/etc',
    '/lib',
    '/lib32',
    '/lib64',
    '/opt',
    '/sbin',
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
    '/var/lib/alsa/asound.state',
    '/var/lib/dbus/machine-id',
    '/var/lib/dhcp/dhcpd.leases',
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
    *glob('/usr/share/icons/*/icon-theme.cache'),
    *glob('/usr/share/fonts/**/.uuid', recursive=True),
    *glob('/usr/share/fonts/*/*.dir'),
    *glob('/usr/share/fonts/*/*.scale'),
    *glob('/usr/src/linux*'),  # Ignore kernel source directories
}


def main(args: argparse.Namespace) -> None:
    tracked = collect_tracked_files()
    dirs_to_check = args.paths or DIRS_TO_CHECK
    for dirname in dirs_to_check:

        for dirpath, dirnames, filenames in os.walk(dirname, topdown=True):
            if not args.strict:
                # Modify dirnames in-place to apply whitelist filter
                dirnames[:] = [d for d in dirnames
                               if os.path.join(dirpath, d) not in WHITELIST]

            for name in filenames:
                filepath = os.path.join(dirpath, name)
                if any(f in tracked for f in resolve_symlinks(filepath)):
                    continue
                if args.strict is False and should_ignore_path(filepath):
                    continue

                print(filepath)


def should_ignore_path(filepath: str) -> bool:
    """Relative path checks"""

    if filepath in WHITELIST:
        return True

    filename, ext = os.path.splitext(os.path.basename(filepath))
    # Ignore .keep files to indicate no-delete folders
    if filename == '.keep':
        return True

    dirname = os.path.basename(os.path.dirname(filepath))
    # Ignore python cached bytecode files
    if dirname == '__pycache__' and ext == '.pyc':
        return True

    return False


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
        '--strict',
        help='run in strict mode',
        action='store_true'
    )
    parser.add_argument(
        '-p', '--path',
        action='append',
        metavar='PATH',
        dest='paths',
        help='override default directories, can be passed multiple times. '
             '(default: {})'.format(' '.join(DIRS_TO_CHECK))
    )
    parser.add_argument(
        '-v', '--version',
        action='version',
        version='%(prog)s {}'.format(VERSION)
    )
    main(parser.parse_args())
