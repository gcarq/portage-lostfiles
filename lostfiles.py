#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import itertools
import os
import psutil
from glob import glob
from pathlib import Path
from typing import List, Set

import pkg_resources

PORTAGE_DB = "/var/db/pkg"
DIRS_TO_CHECK = {
    "/bin",
    "/etc",
    "/lib",
    "/lib32",
    "/lib64",
    "/opt",
    "/sbin",
    "/usr",
    "/var",
}

# Every path defined in whitelist is ignored
WHITELIST = {
    "/etc/.etckeeper",
    "/etc/.git",
    "/etc/.gitignore",
    "/etc/.pwd.lock",
    "/etc/.updated",
    "/etc/crypttab",
    "/etc/fstab",
    "/etc/group",
    "/etc/group-",
    "/etc/gshadow",
    "/etc/gshadow-",
    "/etc/hostname",
    "/etc/ld.so.cache",
    "/etc/ld.so.conf",
    "/etc/locale.conf",
    "/etc/localtime",
    "/etc/machine-id",
    "/etc/mtab",
    "/etc/passwd",
    "/etc/passwd-",
    "/etc/portage",
    "/etc/resolv.conf",
    "/etc/shadow",
    "/etc/shadow-",
    "/etc/subgid",
    "/etc/subgid-",
    "/etc/subuid",
    "/etc/subuid-",
    "/etc/profile.env",
    "/etc/profile.csh",
    "/etc/make.conf",
    "/etc/csh.env",
    "/etc/timezone",
    "/etc/udev/hwdb.bin",
    "/etc/vconsole.conf",
    "/etc/env.d/02locale",
    "/etc/env.d/04gcc-x86_64-pc-linux-gnu",
    "/etc/env.d/05binutils",
    "/etc/env.d/99editor",
    "/etc/env.d/binutils/config-x86_64-pc-linux-gnu",
    "/etc/env.d/gcc/config-x86_64-pc-linux-gnu",
    "/etc/ld.so.conf.d/05gcc-x86_64-pc-linux-gnu.conf",
    "/etc/environment.d/10-gentoo-env.conf",
    "/usr/bin/c89",
    "/usr/bin/c99",
    "/usr/lib/ccache",
    "/usr/lib64/gconv/gconv-modules.cache",
    "/usr/portage",
    "/usr/sbin/fix_libtool_files.sh",
    "/usr/share/applications/mimeinfo.cache",
    "/usr/share/fonts/.uuid",
    "/usr/share/info/dir",
    "/usr/share/mime",
    "/var/.updated",
    "/var/cache",
    "/var/db",
    "/var/lib/alsa/asound.state",
    "/var/lib/chkboot",
    "/var/lib/dbus/machine-id",
    "/var/lib/dhcp/dhcpd.leases",
    "/var/lib/flatpak",
    "/var/lib/gentoo/news",
    "/var/lib/layman",
    "/var/lib/module-rebuild/moduledb",
    "/var/lib/portage",
    "/var/lib/sddm/.cache",
    "/var/lock",
    "/var/log",
    "/var/run",
    "/var/spool",
    "/var/tmp",
    *glob("/etc/ssl/*"),
    *glob("/usr/share/gcc-data/*/*/info/dir"),
    *glob("/usr/share/binutils-data/*/*/info/dir"),
    *glob("/lib*/modules"),  # Ignore all kernel modules
    *glob("/usr/lib*/locale/locale-archive"),
    *glob("/usr/share/.mono/*/Trust"),
    *glob("/usr/share/icons/*/icon-theme.cache"),
    *glob("/usr/share/fonts/**/.uuid", recursive=True),
    *glob("/usr/share/fonts/*/*.dir"),
    *glob("/usr/share/fonts/*/*.scale"),
    *glob("/usr/src/linux*"),  # Ignore kernel source directories
    *glob("/var/www/*"),
}

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--strict", help="run in strict mode", action="store_true")
    parser.add_argument(
        "-p",
        "--path",
        action="append",
        metavar="PATH",
        dest="paths",
        help="override default directories, can be passed multiple times. "
        "(default: {})".format(" ".join(DIRS_TO_CHECK)),
    )
    parser.add_argument(
        "-v",
        "--version",
        action="version",
        version="%(prog)s {}".format(pkg_resources.require("lostfiles")[0].version),
    )
    return parser.parse_args()

def packages():
    if package_exist("app-admin/system-config-printer"):
        WHITELIST.update({*glob("/usr/share/system-config-printer/*.pyc")})

    if package_exist("app-editors/vim"):
        WHITELIST.update({"/usr/share/vim/vim82/doc/tags"})

    if package_exist("app-emulation/docker"):
        WHITELIST.update({"/etc/docker/key.json"})

    if package_exist("app-emulation/libvirt"):
        WHITELIST.update({*glob("/etc/libvirt/nwfilter/*.xml")})
        WHITELIST.update({*glob("/etc/libvirt/qemu/*.xml")})
        WHITELIST.update({*glob("/etc/libvirt/qemu/autostart/*.xml")})
        WHITELIST.update({*glob("/etc/libvirt/qemu/networks/*.xml")})
        WHITELIST.update({*glob("/etc/libvirt/qemu/networks/autostart/*.xml")})
        WHITELIST.update({*glob("/etc/libvirt/storage/*.xml")})
        WHITELIST.update({*glob("/etc/libvirt/storage/autostart/*.xml")})

    if package_exist("app-i18n/ibus"):
        WHITELIST.update({"/etc/dconf/db/ibus"})

    if package_exist("app-text/docbook-xml-dtd"):
        WHITELIST.update({"/etc/xml/catalog"})
        WHITELIST.update({"/etc/xml/docbook"})

    if package_exist("app-office/libreoffice") or package_exist("app-office/libreoffice-bin"):
        WHITELIST.update({"/usr/lib64/libreoffice/program/resource/common/fonts/.uuid"})
        WHITELIST.update({"/usr/lib64/libreoffice/share/fonts/truetype/.uuid"})

    if package_exist("dev-db/mariadb"):
        WHITELIST.update({*glob("/etc/mysql/mariadb.d/*.cnf")})

    if package_exist("dev-lang/php"):
        WHITELIST.update({*glob("/etc/php/fpm*/fpm.d/*")})

    if package_exist("dev-libs/nss"):
        WHITELIST.update({"/usr/lib64/libfreebl3.chk"})
        WHITELIST.update({"/usr/lib64/libnssdbm3.chk"})
        WHITELIST.update({"/usr/lib64/libsoftokn3.chk"})

    if package_exist("net-misc/dhcpcd"):
        WHITELIST.update({"/etc/dhcpcd.duid"})

    if package_exist("net-misc/dhcp"):
        WHITELIST.update({*glob("/etc/dhcp/dhclient-*.conf")})

    if package_exist("net-print/cups"):
        WHITELIST.update({"/etc/printcap"})
        WHITELIST.update({"/etc/cups/classes.conf"})
        WHITELIST.update({"/etc/cups/ppd"})
        WHITELIST.update({"/etc/cups/ssl"})
        WHITELIST.update({"/etc/cups/printers.conf"})
        WHITELIST.update({"/etc/cups/subscriptions.conf"})
        WHITELIST.update({*glob("/etc/cups/*.O")})

    if package_exist("dev-php/PEAR-PEAR"):
        WHITELIST.update({"/usr/share/php/.channels"})
        WHITELIST.update({"/usr/share/php/.packagexml"})
        WHITELIST.update({"/usr/share/php/.registry"})
        WHITELIST.update({"/usr/share/php/.filemap"})
        WHITELIST.update({"/usr/share/php/.lock"})
        WHITELIST.update({"/usr/share/php/.depdblock"})
        WHITELIST.update({"/usr/share/php/.depdb"})

    if package_exist("media-video/vlc"):
        WHITELIST.update({"/usr/lib64/vlc/plugins/plugins.dat"})

    if package_exist("net-misc/openssh"):
        WHITELIST.update({*glob("/etc/ssh/ssh_host_*")})

    if package_exist("net-misc/teamviewer"):
        WHITELIST.update({*glob("/etc/teamviewer*/global.conf")})
        WHITELIST.update({*glob("/opt/teamviewer*/rolloutfile.*")})

    if package_exist("net-vpn/openvpn"):
        WHITELIST.update({*glob("/etc/openvpn/*")})

    if package_exist("sys-apps/lm-sensors"):
        WHITELIST.update({"/etc/modules-load.d/lm_sensors.conf"})

    if package_exist("sys-fs/lvm2"):
        WHITELIST.update({*glob("/etc/lvm/backup/*")})
        WHITELIST.update({*glob("/etc/lvm/archive/*")})
        WHITELIST.update({"/etc/lvm/cache/.cache"})

    if package_exist("sys-libs/cracklib"):
        WHITELIST.update({*glob("/usr/lib/cracklib_dict.*")})

    if check_process("systemd"):
        WHITELIST.update({"/etc/systemd/network"})
        WHITELIST.update({"/etc/systemd/user"})
        WHITELIST.update({"/var/lib/systemd"})
    else:
        WHITELIST.update({"/etc/adjtime"})

def main() -> None:
    args = parse_args()
    dirs_to_check = args.paths or DIRS_TO_CHECK
    tracked = collect_tracked_files()

    packages()

    for dirname in dirs_to_check:

        for dirpath, dirnames, filenames in os.walk(dirname, topdown=True):
            if not args.strict:
                # Modify dirnames in-place to apply whitelist filter
                dirnames[:] = [
                    d for d in dirnames if os.path.join(dirpath, d) not in WHITELIST
                ]

            for name in filenames:
                filepath = os.path.join(dirpath, name.encode('utf-8', 'replace').decode())
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
    if filename == ".keep":
        return True

    dirname = os.path.basename(os.path.dirname(filepath))
    # Ignore python cached bytecode files
    if dirname == "__pycache__" and ext == ".pyc":
        return True

    return False

def check_process(process_name: str) -> bool:
    """
    Check process is running based on name.
    """
    for proc in psutil.process_iter():
        if proc.name() == process_name:
            return True

    return False

def resolve_symlinks(*paths) -> Set[str]:
    return set(
        itertools.chain.from_iterable((path, os.path.realpath(path)) for path in paths)
    )

def package_exist(name: str) -> bool:
	for file in glob(PORTAGE_DB + "/" + name + "-[1-9]*"):
		if os.path.isdir(file):
			return True

	return False

def normalize_filenames(files: List[str]) -> Set[str]:
    """Normalizes a list of CONTENT and returns a set of absolute file paths"""
    normalized = set()
    for f in files:
        ctype, rem = f.rstrip().split(" ", maxsplit=1)
        if ctype == "dir":
            # format: dir <path>
            normalized.update(resolve_symlinks(rem))

        elif ctype == "obj":
            # format: obj <path> <md5sum> <unixtime>
            parts = rem.rsplit(" ", maxsplit=2)
            assert len(parts) == 3, "unknown obj syntax definition for: %s" % f
            normalized.update(resolve_symlinks(parts[0]))

        elif ctype == "sym":
            # format: sym <source> -> <target> <unixtime>
            parts = rem.split(" -> ")
            assert len(parts) == 2, "unknown obj syntax definition for: %s" % f
            sym_origin = parts[0]
            sym_dest = parts[1].rsplit(" ", maxsplit=1)[0]
            if sym_dest.startswith("/"):
                sym_target = sym_dest
            else:
                sym_target = os.path.join(os.path.dirname(sym_origin), sym_dest)
            normalized.update(resolve_symlinks(sym_origin, sym_target))

        else:
            raise AssertionError("Unknown content type: %s" % ctype)

    return normalized


def collect_tracked_files() -> Set[str]:
    """Returns a set of files tracked by portage"""
    files = set()
    for filename in Path(PORTAGE_DB).glob("**/CONTENTS"):
        with open(str(filename), mode="r") as fp:
            files.update(normalize_filenames(fp.readlines()))

    if not files:
        raise AssertionError("No tracked files found. This is probably a bug!")
    return files

if __name__ == "__main__":
    main()
