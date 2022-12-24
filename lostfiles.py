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

PKG_PATHS = {
    "app-admin/logrotate": {
        "/etc/logrotate.d",
    },
    "app-admin/salt": {
        "/etc/salt/minion.d/_schedule.conf",
        "/etc/salt/minion_id",
        "/etc/salt/pki",
    },
    "app-admin/sudo": {
        "/etc/sudoers.d",
    },
    "app-backup/bareos": {
        *glob("/etc/bareos/*/*/*.conf"),
    },
    "app-crypt/certbot": {
        "/etc/letsencrypt/accounts",
        "/etc/letsencrypt/archive",
        "/etc/letsencrypt/live",
        *glob("/etc/letsencrypt/csr/*.pem"),
        *glob("/etc/letsencrypt/keys/*.pem"),
        *glob("/etc/letsencrypt/renewal/*.conf"),
    },
    "app-containers/docker": {
        "/etc/docker/key.json",
        "/var/lib/docker",
    },
    "app-emulation/libvirt": {
        *glob("/etc/libvirt/nwfilter/*.xml"),
        *glob("/etc/libvirt/qemu/*.xml"),
        *glob("/etc/libvirt/qemu/autostart/*.xml"),
        *glob("/etc/libvirt/qemu/networks/*.xml"),
        *glob("/etc/libvirt/qemu/networks/autostart/*.xml"),
        *glob("/etc/libvirt/storage/*.xml"),
        *glob("/etc/libvirt/storage/autostart/*.xml"),
    },
    "app-emulation/lxd": {
        "/var/lib/lxd",
    },
    "app-i18n/ibus": {
        "/etc/dconf/db/ibus",
    },
    "dev-db/mariadb": {
        *glob("/etc/mysql/mariadb.d/*.cnf"),
    },
    "dev-lang/php": {
        "/etc/php/fpm*/fpm.d",
    },
    "dev-libs/nss": {
        *glob("/usr/lib*/libfreebl3.chk"),
        *glob("/usr/lib*/libnssdbm3.chk"),
        *glob("/usr/lib*/libsoftokn3.chk"),
    },
    "net-dialup/ppp": {
        "/etc/ppp/chap-secrets",
        "/etc/ppp/pap-secrets",
        "/etc/ppp/ip-down.d",
        "/etc/ppp/ip-up.d",
    },
    "net-dns/bind": {
        "/etc/bind/rndc.key",
        "/etc/bind/rndc.conf",
        "/var/bind",
    },
    "net-fs/samba": {
        "/etc/samba/smb.conf",
        "/etc/samba/smbusers",
    },
    "net-misc/dhcpcd": {
        "/etc/dhcpcd.duid",
    },
    "net-misc/dhcp": {
        *glob("/etc/dhcp/dhclient-*.conf"),
    },
    "net-misc/dahdi-tools": {
        *glob("/etc/dahdi/assigned-spans.*"),
        *glob("/etc/dahdi/system.*"),
    },
    "net-print/cups": {
        "/etc/printcap",
        "/etc/cups/classes.conf",
        "/etc/cups/ppd",
        "/etc/cups/ssl",
        "/etc/cups/printers.conf",
        "/etc/cups/subscriptions.conf",
        *glob("/etc/cups/*.O"),
    },
    "dev-lang/mono": {
        *glob("/usr/share/.mono/*/Trust"),
    },
    "dev-php/PEAR-PEAR": {
        "/usr/share/php/.channels",
        "/usr/share/php/.packagexml",
        "/usr/share/php/.registry",
        "/usr/share/php/.filemap",
        "/usr/share/php/.lock",
        "/usr/share/php/.depdblock",
        "/usr/share/php/.depdb",
    },
    "mail-filter/rspamd": {
        "/etc/rspamd/local.d",
    },
    "mail-filter/spamassassin": {
        "/etc/mail/spamassassin/sa-update-keys",
    },
    "mail-mta/exim": {
        "/etc/exim/exim.conf",
    },
    "media-video/vlc": {
        *glob("/usr/lib*/vlc/plugins/plugins.dat"),
    },
    "media-gfx/graphviz": {
        *glob("/usr/lib*/graphviz/config6"),
    },
    "net-analyzer/librenms": {
        "/opt/librenms/.composer",
        "/opt/librenms/bootstrap/cache",
        "/opt/librenms/config.php",
        "/opt/librenms/logs/",
        "/opt/librenms/rrd/",
        "/opt/librenms/vendor",
    },
    "net-analyzer/net-snmp": {
        "/etc/snmp/snmpd.conf",
    },
    "net-firewall/firehol": {
        "/etc/firehol/firehol.conf",
        "/etc/firehol/fireqos.conf",
        "/etc/firehol/ipsets",
        "/etc/firehol/services",
    },
    "net-misc/openssh": {
        *glob("/etc/ssh/ssh_host_*"),
    },
    "net-misc/teamviewer": {
        *glob("/etc/teamviewer*/global.conf"),
        *glob("/opt/teamviewer*/rolloutfile.*"),
    },
    "net-ftp/proftpd": {
        "/etc/proftpd/proftpd.conf",
    },
    "sys-apps/lm-sensors": {
        "/etc/modules-load.d/lm_sensors.conf",
    },
    "sys-fs/cryptsetup": {
        "/etc/crypttab",
    },
    "sys-fs/lvm2": {
        "/etc/lvm/backup",
        "/etc/lvm/archive",
        "/etc/lvm/cache/.cache",
    },
    "sys-libs/cracklib": {
        *glob("/usr/lib*/cracklib_dict.*"),
    },
    "www-apps/guacamole-client": {
        "/etc/guacamole/lib",
        *glob("/etc/guacamole/extensions/*.jar"),
    },
    "www-servers/tomcat": {
        *glob("/etc/conf.d/tomcat-*"),
        *glob("/etc/init.d/tomcat-*"),
        *glob("/etc/runlevels/*/tomcat-*"),
        *glob("/etc/tomcat-*"),
        *glob("/var/lib/tomcat-*"),
    },
}

# All paths defined in this set will be ignored as they are part of almost every linux system
IGNORED_PATHS = {
    "/etc/.etckeeper",
    "/etc/.git",
    "/etc/.gitignore",
    "/etc/.pwd.lock",
    "/etc/.updated",
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
    "/etc/motd",
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
    "/var/lib/flatpak",
    "/var/lib/gentoo/news",
    "/var/lib/module-rebuild/moduledb",
    "/var/lib/portage",
    "/var/lock",
    "/var/log",
    "/var/run",
    "/var/spool",
    "/var/tmp",
    "/etc/ssl",
    "/etc/sysctl.d",
    "/var/www",
    *glob("/usr/share/gcc-data/*/*/info/dir"),
    *glob("/usr/share/binutils-data/*/*/info/dir"),
    *glob("/lib*/modules"),  # Ignore all kernel modules
    *glob("/usr/lib*/gconv/gconv-modules.cache"),  # used by glibc
    *glob("/usr/lib*/locale/locale-archive"),  # used by glibc
    *glob("/usr/share/icons/*/icon-theme.cache"),
    *glob("/usr/share/fonts/**/.uuid", recursive=True),
    *glob("/usr/share/fonts/*/*.dir"),
    *glob("/usr/share/fonts/*/*.scale"),
    *glob("/usr/src/linux*"),  # Ignore kernel source directories
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
                process_files(dirpath, sorted(filenames), args.strict, tracked)
            except IgnoreDirectory:
                if not args.strict:
                    dirnames[:] = []
            else:
                if not args.strict:
                    dirnames[:] = [
                        d for d in dirnames if os.path.join(dirpath, d) not in IGNORED_PATHS
                    ]


def process_files(dirpath: str, filenames: list[str], strict: bool, tracked: set[str]) -> None:
    """
    Processes filenames found in the given `dirpath`, if a keepfile is found
    and the corresponding package is installed a `IgnoreDirectory` exception
    is raised to indicate this and all subdirectories should be ignored.
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

    for name in filenames:
        filepath = os.path.join(dirpath, name.encode("utf-8", "replace").decode())
        if any(f in tracked for f in resolve_symlinks(filepath)):
            continue
        if not strict and should_ignore_path(filepath):
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


def resolve_symlinks(*paths: str) -> set[str]:
    return set(itertools.chain.from_iterable((p, os.path.realpath(p)) for p in paths))


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
            normalized.update(resolve_symlinks(path))

        elif cid == "obj":
            # format: obj <unixtime> <md5sum>
            normalized.update(resolve_symlinks(path))

        elif cid == "sym":
            # format: sym <unixtime> <target>
            _, sym_dest = additional_fields
            if sym_dest.startswith("/"):
                sym_target = sym_dest
            else:
                sym_target = os.path.join(os.path.dirname(path), sym_dest)
            normalized.update(resolve_symlinks(path, sym_target))

        else:
            raise AssertionError(f"Unknown content type: {cid}")

    return normalized


def get_contents_for_pkg(atom: str) -> set[str]:
    """
    Returns all paths listed in CONTENTS for each package for the given package atom
    """
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
