#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import itertools
import os
import psutil
import time
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

PKG_PATHS = {
    "app-admin/logrotate": {
        "/etc/logrotate.d",
    },
    "app-admin/salt": {
        "/etc/salt/minion.d/_schedule.conf",
        "/etc/salt/minion_id",
        "/etc/salt/pki/*",
    },
    "app-admin/sudo": {
        "/etc/sudoers.d",
    },
    "app-admin/system-config-printer": {
        "/usr/share/system-config-printer/*.pyc",
    },
    "app-backup/bareos": {
        "/etc/bareos/*/*/*.conf"
    },
    "app-crypt/certbot": {
        "/etc/letsencrypt/accounts",
        "/etc/letsencrypt/archive",
        "/etc/letsencrypt/csr/*.pem",
        "/etc/letsencrypt/keys/*.pem",
        "/etc/letsencrypt/live",
        "/etc/letsencrypt/renewal/*.conf",
    },
    "app-editors/vim": {
        "/usr/share/vim/vim82/doc/tags",
    },
    "app-emulation/docker": {
        "/etc/docker/key.json",
    },
    "app-emulation/libvirt": {
        "/etc/libvirt/nwfilter/*.xml",
        "/etc/libvirt/qemu/*.xml",
        "/etc/libvirt/qemu/autostart/*.xml",
        "/etc/libvirt/qemu/networks/*.xml",
        "/etc/libvirt/qemu/networks/autostart/*.xml",
        "/etc/libvirt/storage/*.xml",
        "/etc/libvirt/storage/autostart/*.xml",
    },
    "app-i18n/ibus": {
        "/etc/dconf/db/ibus",
    },
    "app-text/docbook-xml-dtd": {
        "/etc/xml/catalog",
        "/etc/xml/docbook",
    },
    "dev-db/mariadb": {
        "/etc/mysql/mariadb.d/*.cnf",
    },
    "dev-lang/php": {
        "/etc/php/fpm*/fpm.d/*",
    },
    "dev-libs/nss": {
        "/usr/lib*/libfreebl3.chk",
        "/usr/lib*/libnssdbm3.chk",
        "/usr/lib*/libsoftokn3.chk",
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
        "/etc/dhcp/dhclient-*.conf",
    },
    "net-misc/dahdi-tools": {
        "/etc/dahdi/assigned-spans.*",
        "/etc/dahdi/system.*",
    },
    "net-print/cups": {
        "/etc/printcap",
        "/etc/cups/classes.conf",
        "/etc/cups/ppd",
        "/etc/cups/ssl",
        "/etc/cups/printers.conf",
        "/etc/cups/subscriptions.conf",
        "/etc/cups/*.O",
    },
    "dev-lang/mono": {
        "/usr/share/.mono/*/Trust",
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
        "/etc/rspamd/local.d/*",
    },
    "mail-filter/spamassassin": {
        "/etc/mail/spamassassin/sa-update-keys",
    },
    "mail-mta/exim": {
        "/etc/exim/exim.conf",
    },
    "media-video/vlc": {
        "/usr/lib*/vlc/plugins/plugins.dat",
    },
    "media-gfx/graphviz": {
        "/usr/lib*/graphviz/config6",
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
    "net-misc/geoipupdate": {
        "/usr/share/GeoIP",
    },
    "net-misc/openssh": {
        "/etc/ssh/ssh_host_*",
    },
    "net-misc/teamviewer": {
        "/etc/teamviewer*/global.conf",
        "/opt/teamviewer*/rolloutfile.*",
    },
    "net-ftp/proftpd": {
        "/etc/proftpd/proftpd.conf",
    },
    "net-vpn/openvpn": {
        "/etc/openvpn",
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
        "/usr/lib*/cracklib_dict.*",
    },
    "www-apps/guacamole-client": {
        "/etc/guacamole/lib/*",
        "/etc/guacamole/extensions/*.jar",
    },
    "www-servers/tomcat": {
        "/etc/conf.d/tomcat-*",
        "/etc/init.d/tomcat-*",
        "/etc/runlevels/*/tomcat-*",
        "/etc/tomcat-*",
        "/var/lib/tomcat-*",
    },
}

# Every path defined in whitelist is ignored
WHITELIST = {
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
    *glob("/etc/sysctl.d/*"),
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
    *glob("/var/www/*"),
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--age", help="show the age of the file in seconds, hours or days", action="store_true")
    parser.add_argument("--ask", help="ask to remove each file", action="store_true")
    parser.add_argument(
            "-e",
            "--exclude",
            action="append",
            metavar="PATH",
            dest="exclude",
            help="append files or directories to whitelist",
        )
    parser.add_argument(
            "-E",
            "--excludeconfig",
            help="append files or directories to whitelist from config file",
            type=argparse.FileType('r'),
        )
    parser.add_argument("--human", help="print sizes in human readable format (e.g., 1K 234M 2G)", action="store_true")
    parser.add_argument("--strict", help="run in strict mode", action="store_true")
    parser.add_argument("--verbose", help="show last modified date and file size", action="store_true")
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


def installed_packages():
    for pkg, directories in PKG_PATHS.items():
        if package_exist(pkg):
            whitelist_append(directories)

    if package_exist("sys-process/dcron") or package_exist("sys-process/cronie") or package_exist("sys-process/fcron"):
        WHITELIST.update({"/etc/cron.daily"})
        WHITELIST.update({"/etc/cron.monthly"})
        WHITELIST.update({"/etc/cron.weekly"})

    if package_exist("app-office/libreoffice") or package_exist("app-office/libreoffice-bin"):
        WHITELIST.update({*glob("/usr/lib*/libreoffice/program/resource/common/fonts/.uuid")})
        WHITELIST.update({*glob("/usr/lib*/libreoffice/share/fonts/truetype/.uuid")})

    if check_process("systemd"):
        WHITELIST.update({"/etc/systemd/network"})
        WHITELIST.update({"/etc/systemd/user"})
        WHITELIST.update({"/var/lib/systemd"})
    else:
        WHITELIST.update({"/etc/adjtime"})
        WHITELIST.update({"/etc/conf.d/net"})


def whitelist_append(directories: List[str]) -> None:
    for directory in directories:
        for file in glob(directory.strip()):
            WHITELIST.update({file})


def yes_no(question: str, default: bool or None = None) -> bool:
    if default is None:
        prompt = " [y/n]"
    elif default is True:
        prompt = " [Y/n]"
    elif default is False:
        prompt = " [y/N]"

    yes = set(['yes', 'y', 'true'])
    no = set(['no', 'n', 'false'])

    while True:
        choice = input(question + prompt + "? ").strip().lower()
        if not choice and default is not None:
            return default
        elif choice in yes:
            return True
        elif choice in no:
            return False
        else:
            print("Please respond with ({} ".format(", ".join(yes)) + ",{}".format(", ".join(no)) + ")\n")


def main() -> None:
    args = parse_args()
    dirs_to_check = args.paths or DIRS_TO_CHECK

    tracked = collect_tracked_files()

    if args.exclude:
        whitelist_append(args.exclude)
    if args.excludeconfig:
        whitelist_append(args.excludeconfig.readlines())

    installed_packages()

    totalFiles: int = 0
    totalFilesRemove: int = 0
    totalSize: int = 0

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

                totalFiles += 1
                if args.verbose is True and os.path.isfile(filepath):
                    fileSize = os.path.getsize(filepath)
                    fileTime = os.path.getmtime(filepath)

                    totalSize += fileSize

                    if args.age is True:
                        fileTime = format_age(fileTime)
                    else:
                        fileTime = time.ctime(fileTime)

                    if args.human is True:
                        fileSize = format_size(fileSize)
                    else:
                        fileSize = str(fileSize)

                    print(filepath + " | " + fileTime + " | " + fileSize)
                else:
                    print(filepath)

                if args.ask is True:
                    if yes_no("Remove", False):
                        os.remove(filepath)
                        totalFilesRemove += 1

    if args.verbose is True:
        print("-------------")
        print("Total files: " + str(totalFiles))
        if args.ask is True:
            print("Total files removed: " + str(totalFilesRemove))
        if args.human is True:
            totalSize = format_size(totalSize)
        print("Total file size: " + str(totalSize))


def format_age(fileTime: int) -> str:
    timeUnitList = (
        ('s', 60),
        ('m', 60),
        ('h', 24),
    )
    age = time.time() - fileTime
    for unit, step in timeUnitList:
        if (age < step):
            return "%i%s" % (age, unit)
        age = age / step

    return "%i%s" % (age, "d")


def format_size(sizeInBytes: int, decimalNum: int = 2, isUnitWithI: bool = False, sizeUnitSeparator: str = "") -> str:
    """format size to human readable string"""
    # https://en.wikipedia.org/wiki/Binary_prefix#Specific_units_of_IEC_60027-2_A.2_and_ISO.2FIEC_80000
    # K=kilo, M=mega, G=giga, T=tera, P=peta, E=exa, Z=zetta, Y=yotta
    sizeUnitList = ['', 'K', 'M', 'G', 'T', 'P', 'E', 'Z']
    largestUnit = 'Y'

    if isUnitWithI:
        sizeUnitListWithI = []
        for curIdx, eachUnit in enumerate(sizeUnitList):
            unitWithI = eachUnit
            if curIdx >= 1:
                unitWithI += 'i'
            sizeUnitListWithI.append(unitWithI)

        # sizeUnitListWithI = ['','Ki','Mi','Gi','Ti','Pi','Ei','Zi']
        sizeUnitList = sizeUnitListWithI

        largestUnit += 'i'

    suffix = "B"
    decimalFormat = "." + str(decimalNum) + "f"  # ".1f"
    finalFormat = "%" + decimalFormat + sizeUnitSeparator + "%s%s"  # "%.1f%s%s"
    sizeNum = sizeInBytes
    for sizeUnit in sizeUnitList:
        if abs(sizeNum) < 1024.0:
            if (isinstance(sizeNum, int)):
                return ("%i" + sizeUnitSeparator + "%s%s") % (sizeNum, sizeUnit, suffix)
            else:
                return finalFormat % (sizeNum, sizeUnit, suffix)
        sizeNum /= 1024.0

    return finalFormat % (sizeNum, largestUnit, suffix)


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
    for file in glob(PORTAGE_DB + "/" + name + "-[0-9]*"):
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
            for line in fp.readlines():
                line = line.encode("utf-8", "replace").decode()
                files.update(normalize_filenames({line}))

    if not files:
        raise AssertionError("No tracked files found. This is probably a bug!")
    return files


if __name__ == "__main__":
    main()
