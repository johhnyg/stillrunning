"""Test isolation for the published client (v2.13.7).

A test run once burned this box's free API quota: importing stillrunning.hook
left the import finder installed and every later import made a real HTTPS
call to stillrunning.io. Nothing in tests may reach the network, write the
user's ~/.stillrunning state, or leave a meta_path finder behind."""
import os
import sys
import urllib.request

import pytest

os.environ["STILLRUNNING_DISABLE"] = "1"

# Tests that only make sense on POSIX, skipped on Windows by exact name.
_WINDOWS_SKIP = {
    # The pip/npm shell wrappers (`stillrunning shell-install`) are POSIX shell
    # scripts, documented as not supported on Windows; these run them with sh/bash.
    "posix shell wrapper (not supported on Windows, README Platforms)": {
        "test_s135_claude_hook.py": {
            "test_wrapper_urls_and_custom_indexes_need_approval",
            "test_wrapper_unverified_stops_without_a_terminal",
            "test_wrapper_says_clearly_when_the_real_tool_is_missing",
            "test_wrappers_pass_through_everything_else",
            "test_wrapper_never_execs_itself_or_another_copy_of_itself",
            "test_wrapper_index_from_environment_needs_approval",
            "test_wrapper_allow_unverified_warns_and_proceeds",
        },
        "test_s135_review_fixes.py": {
            "test_pip_wrapper_treats_an_attached_custom_index_as_unverified",
            "test_wrapper_opt_out_never_installs_a_listed_package",
            "test_pip_wrapper_tells_scan_when_the_version_is_not_the_latest",
            "test_wrapper_opt_out_still_covers_the_unverified_case",
            "test_python_m_pip_behind_interpreter_flags_reaches_the_wrapper",
            "test_pip_wrapper_separate_index_flag_still_stops",
            "test_pip_wrapper_reads_attached_requirement_flags",
            "test_npm_wrapper_checks_update_and_link",
        },
    },
    # POSIX permission bits / owners / symlinks: Windows synthesizes the mode
    # bits (files 0o666, folders 0o777), has no os.getuid, and the client skips
    # these checks there by design (verdict_cache._POSIX_MODES, claude_hook
    # _private_state_dir); creating symlinks needs extra privileges.
    "posix file modes, owners or symlinks": {
        "test_panel.py": {"test_report_round_trips_through_the_saved_file"},
        "test_remembered.py": {"test_remember_last_then_list_touch_forget"},
        "test_s135_review3_fixes.py": {"test_state_folder_is_created_owner_only_and_an_open_one_is_closed"},
        "test_verdict_cache.py": {
            "test_db_writable_by_others_is_never_served",
            "test_db_owned_by_another_account_is_never_served",
            "test_a_symlinked_db_is_not_followed",
        },
    },
}


def pytest_collection_modifyitems(config, items):
    if os.name != "nt":
        return
    for reason, by_file in _WINDOWS_SKIP.items():
        mark = pytest.mark.skip(reason=f"Windows: {reason}")
        for item in items:
            names = by_file.get(os.path.basename(str(item.fspath)), ())
            if getattr(item, "originalname", item.name) in names:
                item.add_marker(mark)


@pytest.fixture(autouse=True)
def _isolated(monkeypatch, tmp_path):
    if os.name == "nt":
        # Windows finds the home folder through USERPROFILE and ignores HOME, so
        # a test's HOME never reached the code under test and every test shared
        # the runner's real profile. Give each test its own, and make a test's
        # monkeypatch.setenv("HOME", ...) move USERPROFILE with it.
        home = tmp_path / "_userprofile"
        home.mkdir(exist_ok=True)
        _setenv = monkeypatch.setenv

        def setenv(name, value, prepend=None):
            _setenv(name, value, prepend)
            if name == "HOME":
                _setenv("USERPROFILE", str(value))
        monkeypatch.setenv = setenv
        _setenv("USERPROFILE", str(home))
        _setenv("HOME", str(home))

    def _no_network(*a, **k):
        raise RuntimeError("network access is disabled in tests — stub urlopen explicitly")
    monkeypatch.setattr(urllib.request, "urlopen", _no_network)
    monkeypatch.delenv("STILLRUNNING_TOKEN", raising=False)
    if "stillrunning.hook" in sys.modules:
        monkeypatch.setattr(sys.modules["stillrunning.hook"], "SEEN_PATH", tmp_path / "import_checks.json")
    yield
    # never leave a stillrunning finder installed between tests
    sys.meta_path[:] = [f for f in sys.meta_path if "stillrunning" not in type(f).__module__]
