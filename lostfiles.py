#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import itertools
import os
from glob import glob

import portage
import pkg_resources

# vartree provides an interface to the installed package database.
# See https://dev.gentoo.org/~zmedico/portage/doc/api/portage.dbapi.vartree.html
DB_API = portage.db[portage.root]["vartree"].dbapi

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

# Defines a mapping of package-atoms and paths that should be ignored if the package is installed.
# NOTE: subfolders will also be ignored if a path is written with a trailing slash
PKG_PATHS = {
    "app-admin/salt": {
        "/etc/salt/",
    },
    "app-admin/sudo": {
        "/etc/sudoers.d/",
    },
    "app-backup/bareos": {
        "/etc/bareos/",
    },
    "app-crypt/certbot": {
        "/etc/letsencrypt/",
    },
    "app-containers/docker": {
        "/etc/docker/",
        "/var/lib/docker/",
    },
    "app-emulation/libvirt": {
        "/etc/libvirt/",
    },
    "app-emulation/lxd": {
        "/var/lib/lxd/",
    },
    "app-i18n/ibus": {
        "/etc/dconf/db/ibus",
    },
    "dev-db/mariadb": {
        *glob("/etc/mysql/mariadb.d/*.cnf"),
    },
    "dev-lang/mono": {
        *glob("/usr/share/.mono/*/Trust"),
    },
    "dev-lang/php": {
        "/etc/php/fpm*/fpm.d/",
    },
    "dev-libs/nss": {
        *glob("/usr/lib*/libfreebl3.chk"),
        *glob("/usr/lib*/libnssdbm3.chk"),
        *glob("/usr/lib*/libsoftokn3.chk"),
    },
    "dev-utils/ccache": {
        *glob("/usr/lib*/ccache/"),
    },
    "mail-filter/rspamd": {
        "/etc/rspamd/",
    },
    "mail-filter/spamassassin": {
        "/etc/mail/spamassassin/",
    },
    "mail-mta/exim": {
        "/etc/exim/",
    },
    "media-gfx/graphviz": {
        *glob("/usr/lib*/graphviz/"),
    },
    "media-video/vlc": {
        *glob("/usr/lib*/vlc/plugins/plugins.dat"),
    },
    "net-analyzer/librenms": {
        "/opt/librenms/",
    },
    "net-analyzer/net-snmp": {
        "/etc/snmp/snmpd.conf",
    },
    "net-dialup/ppp": {
        "/etc/ppp/",
    },
    "net-dns/bind": {
        "/etc/bind/",
    },
    "net-firewall/firehol": {
        "/etc/firehol/",
    },
    "net-fs/samba": {
        "/etc/samba/",
    },
    "net-misc/dhcpcd": {
        "/etc/dhcpcd.duid",
    },
    "net-misc/dhcp": {
        "/etc/dhcp/",
    },
    "net-misc/dahdi-tools": {
        *glob("/etc/dahdi/assigned-spans.*"),
        *glob("/etc/dahdi/system.*"),
    },
    "net-misc/networkmanager": {
        "/etc/NetworkManager/conf.d/",
        "/var/lib/NetworkManager/",
    },
    "net-misc/openssh": {
        *glob("/etc/ssh/ssh_host_*"),
    },
    "net-misc/teamviewer": {
        *glob("/opt/teamviewer*/rolloutfile.*"),
    },
    "net-ftp/proftpd": {
        "/etc/proftpd/proftpd.conf",
    },
    "net-print/cups": {
        "/etc/printcap",
        "/etc/cups/",
    },
    "net-wireless/iwd": {
        "/etc/iwd/",
    },
    "sys-apps/accountsservice": {
        "/var/lib/AccountsService/",
    },
    "sys-apps/lm-sensors": {
        "/etc/modules-load.d/lm_sensors.conf",
    },
    "sys-apps/etckeeper": {
        "/etc/.etckeeper",
        "/etc/.git",
        "/etc/.gitignore",
    },
    "sys-apps/flatpak": {
        "/var/lib/flatpak/",
    },
    "sys-apps/fwupd": {
        "/var/lib/fwupd/",
    },
    "sys-apps/systemd": {
        "/etc/.updated",
        "/var/.updated",
    },
    "sys-devel/binutils": {
        "/etc/env.d/05binutils",
        *glob("/etc/env.d/binutils/config-*-*-*"),
        *glob("/usr/share/binutils-data/*/*/info/dir"),
        *glob("/usr/*-*-*/bin"),
        *glob("/usr/*-*-*/lib"),
    },
    "sys-devel/gcc-config": {
        *glob("/etc/ld.so.conf.d/05gcc-*-*-*.conf"),
        *glob("/etc/env.d/04gcc-*-*-*"),
        *glob("/etc/env.d/gcc/config-*-*-*"),
        *glob("/usr/share/gcc-data/*/*/info/dir"),
    },
    "sys-fs/cryptsetup": {
        "/etc/crypttab",
    },
    "sys-fs/lvm2": {
        "/etc/lvm/",
    },
    "sys-libs/cracklib": {
        *glob("/usr/lib*/cracklib_dict.*"),
    },
    "sys-libs/glibc": {
        "/etc/ld.so.conf.d",
        *glob("/usr/lib*/gconv/gconv-modules.cache"),  # used by glibc
        *glob("/usr/lib*/locale/locale-archive"),  # used by glibc
    },
    "virtual/udev": {
        "/etc/udev/hwdb.bin",
    },
    "www-apps/guacamole-client": {
        "/etc/guacamole/",
    },
    "www-servers/tomcat": {
        *glob("/etc/conf.d/tomcat-*"),
        *glob("/etc/init.d/tomcat-*"),
        *glob("/etc/runlevels/*/tomcat-*"),
        *glob("/etc/tomcat-*/"),
        *glob("/var/lib/tomcat-*/"),
    },
    "x11-base/xorg-server": {
        "/etc/X11/xorg.conf.d",
    },
    "x11-misc/sddm": {
        "/etc/sddm.conf",
        "/etc/sddm.conf.d",
        "/etc/sddm.conf.d/kde_settings.conf",
        "/usr/share/sddm/themes/",
    },
}

# All paths defined in this set will be ignored as they are part of almost every linux system.
IGNORED_PATHS = {
    "/etc/.pwd.lock",
    "/etc/csh.env",  # Automatically created via env-update
    "/etc/config-archive/",
    "/etc/env.d/02locale",
    "/etc/env.d/99editor",
    "/etc/environment.d",
    "/etc/environment.d/10-gentoo-env.conf",
    "/etc/fstab",
    "/etc/group",
    "/etc/group-",
    "/etc/gshadow",
    "/etc/gshadow-",
    "/etc/hostname",
    "/etc/ld.so.cache",
    "/etc/ld.so.conf",  # Automatically created via env-update
    "/etc/locale.conf",  # File will be automatically generated
    "/etc/machine-id",
    "/etc/mtab",
    "/etc/motd",
    "/etc/passwd",
    "/etc/passwd-",
    "/etc/portage/",
    "/etc/resolv.conf",
    "/etc/runlevels",
    "/etc/runlevels/sysinit",
    "/etc/runlevels/boot",
    "/etc/shadow",
    "/etc/shadow-",
    "/etc/subgid",
    "/etc/subgid-",
    "/etc/subuid",
    "/etc/subuid-",
    "/etc/profile.env",  # Automatically created via env-update
    "/etc/sysctl.d",
    "/lib/modules/",  # Ignore all kernel modules
    "/usr/local",
    "/usr/local/bin",
    "/usr/local/lib",
    "/usr/local/lib64",
    "/usr/local/sbin",
    "/usr/portage/",
    "/usr/share/applications/mimeinfo.cache",
    *glob("/usr/share/icons/*/icon-theme.cache"),
    "/usr/share/info/dir",
    *glob("/usr/share/fonts/**/.uuid", recursive=True),
    *glob("/usr/share/fonts/*/*.dir"),
    *glob("/usr/share/fonts/*/*.scale"),
    "/usr/share/mime/",
    *glob("/usr/src/linux*/"),  # Ignore kernel source directories
    "/var/cache/",
    "/var/db/",
    "/var/lib/module-rebuild/",
    "/var/lib/run",
    "/var/lib/portage/",
    "/var/lock/",
    "/var/log/",
    "/var/run/",
    "/var/tmp/",
    "/var/www/",
}


class IgnoreDirectory(Exception):
    pass


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


def main() -> None:
    args = parse_args()
    dirs_to_check = args.paths or DIRS_TO_CHECK
    tracked = collect_tracked_files()

    for atom, paths in PKG_PATHS.items():
        if is_pkg_installed(atom):
            IGNORED_PATHS.update(paths)

    for dirname in dirs_to_check:
        for dirpath, dirnames, filenames in os.walk(dirname, topdown=True):
            try:
                process_directory(dirpath, sorted(filenames), args.strict, tracked)
            except IgnoreDirectory:
                if not args.strict:
                    dirnames[:] = []
            else:
                if not args.strict:
                    dirnames[:] = [
                        d for d in dirnames if os.path.join(dirpath, d, "") not in IGNORED_PATHS
                    ]


def process_directory(dirpath: str, filenames: list[str], strict: bool, tracked: set[str]) -> None:
    """
    Processes filenames found in the given `dirpath`, if a keepfile is found
    and the corresponding package is installed a `IgnoreDirectory` exception
    is raised to indicate this and all subdirectories should be ignored
    """
    for name in filenames:
        # In the first iteration we are only looking for the keepfile
        # See https://wiki.gentoo.org/wiki/.keep_file
        if not name.startswith(".keep_"):
            continue

        atom = resolve_pkg_from_keepfile(name)
        if is_pkg_installed(atom):
            raise IgnoreDirectory()
        break

    if not strict:
        paths = resolve_symlink(dirpath)
        if not any(path in tracked or not strict and should_ignore_path(path) for path in paths):
            print(f"{dirpath}/")

    for name in filenames:
        filepath = os.path.join(dirpath, name.encode("utf-8", "replace").decode())
        paths = resolve_symlink(filepath)
        if any(path in tracked or not strict and should_ignore_path(path) for path in paths):
            continue

        print(filepath)


def should_ignore_path(filepath: str) -> bool:
    """Returns `True` if the given path that is not tracked via portage should be ignored"""
    if filepath in IGNORED_PATHS:
        return True

    filename = os.path.basename(filepath)
    # Ignore .keep files that are created by stage tarballs
    if filename == ".keep":
        return True

    return False


def resolve_symlink(path: str) -> set[str]:
    return {path, os.path.realpath(path)}


def resolve_pkg_from_keepfile(filename: str) -> str:
    """
    Returns the package atom from the given .keep file,
    for example: .keep_net-print_cups-0 -> net-print/cups
    """
    _, category, remainder = filename.split("_")
    package, _ = remainder.rsplit("-", maxsplit=1)
    return f"{category}/{package}"


def is_pkg_installed(atom: str) -> bool:
    """Queries the vartree to see if a certain package is installed"""
    return bool(DB_API.cp_list(atom))


def parse_contents(contents: dict[str, tuple]) -> set[str]:
    """Normalizes a list of CONTENT and returns a set of absolute file paths"""
    normalized = set()
    for path, content_type in contents.items():
        cid, *additional_fields = content_type
        if cid == "dir":
            # format: dir
            normalized.add(path)

        elif cid == "obj":
            # format: obj <unixtime> <md5sum>
            normalized.add(path)

        elif cid == "sym":
            # format: sym <unixtime> <target>
            _, sym_dest = additional_fields
            if sym_dest.startswith("/"):
                sym_target = sym_dest
            else:
                sym_target = os.path.abspath(os.path.join(os.path.dirname(path), sym_dest))
            normalized.update((path, sym_target))
        else:
            raise AssertionError(f"Unknown content type: {cid}")

    return normalized


def get_contents_for_pkg(atom: str) -> set[str]:
    """Returns all paths listed in CONTENTS for each package for the given package atom"""
    pkg_names = DB_API.cp_list(atom)
    contents = {
        path: content_type
        for pkg in pkg_names
        for path, content_type in DB_API._dblink(pkg).getcontents().items()
    }
    return parse_contents(contents)


def collect_tracked_files() -> set[str]:
    """Returns a set of files tracked by portage"""
    files_iter = (get_contents_for_pkg(atom) for atom in DB_API.cp_all())
    if files := set(itertools.chain.from_iterable(files_iter)):
        return files

    raise AssertionError("No tracked files found. Please report this as bug!")


if __name__ == "__main__":
    main()
