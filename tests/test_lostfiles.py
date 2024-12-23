from unittest.mock import patch

from lostfiles import resolve_pkg_from_keepfile, should_ignore_path


def test_resolve_pkg_from_keepfile():
    assert resolve_pkg_from_keepfile(".keep_net-print_cups-0") == "net-print/cups"
    assert resolve_pkg_from_keepfile(".keep_sys-apps_systemd-0") == "sys-apps/systemd"
    assert resolve_pkg_from_keepfile(".keep_dir") is None


@patch("lostfiles.IGNORED_PATHS", {"/ignored"})
def test_should_ignore_path(*args, **kwargs):
    assert should_ignore_path("/ignored") is True
    assert should_ignore_path("/not_ignored") is False
    assert should_ignore_path("/not_ignored/.keep") is True
