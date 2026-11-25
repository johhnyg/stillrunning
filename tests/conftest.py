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
            "test_pip_wrapper_outside_a_venv_runs_the_next_pip_on_path",
            "test_pip_wrapper_inside_a_venv_runs_the_venvs_pip",
            "test_pip_wrapper_in_a_venv_without_pip_uses_the_venvs_python",
            "test_pip_wrapper_falls_back_to_python_m_pip",
            "test_npm_wrapper_runs_the_next_npm_on_path",
            "test_pip3_wrapper_runs_pip3",
            "test_shell_install_writes_working_wrappers",
            "test_pip_wrapper_sees_install_after_global_flags",
            "test_pip_wrapper_blocks_a_blocked_package_wherever_install_appears",
            "test_pip_wrapper_skips_flag_values_and_scans_requirement_files",
            "test_npm_wrapper_parses_scoped_names_and_aliases",
            "test_wrapper_layer_is_on_only_when_this_shell_uses_it",
            "test_activating_a_venv_afterwards_does_not_bypass_the_wrapper",
            "test_rc_line_is_harmless_in_plain_sh_and_when_the_files_are_gone",
            "test_shell_uninstall_puts_rc_files_back_byte_for_byte",
            "test_status_sees_the_wrappers_when_a_venv_is_first_on_path",
        },
        "test_v2137_fixes.py": {"test_wrapper_exit_code_policy", "test_wrapper_exit_3_needs_approval"},
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
            "test_db_and_directory_are_owner_only",
            "test_a_loosened_db_mode_is_tightened",
            "test_db_readable_by_others_is_tightened_and_still_ours",
        },
        "test_windows_py38_compat.py": {
            "test_verdict_cache_still_rejects_foreign_files_on_posix",
            "test_hook_state_dir_still_tightened_on_posix",
        },
    },
    # `stillrunning cve --schedule` uses crontab; on Windows it now says so
    # (tests/test_windows_real.py::test_schedule_says_windows_has_no_crontab).
    "crontab scheduling": {
        "test_cve.py": {
            "test_schedule_adds_one_line_is_idempotent_and_unschedule_removes_only_its_own",
            "test_schedule_refuses_when_crontab_cannot_be_read",
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
    # Self-protection cases that put this checkout's path into a command
    # unquoted: on Windows that path has backslashes, which bash itself turns
    # into a different path (D:\\a\\b → D:ab), so the case does not exist there.
    # The forms bash does accept are in tests/test_windows_real.py.
    mangled = pytest.mark.skip(reason="Windows: unquoted backslash path is not that path in bash")
    for item in items:
        if getattr(item, "originalname", "") == "test_commands_that_change_the_protection_ask":
            command = getattr(getattr(item, "callspec", None), "params", {}).get("command", "")
            if "\\" in command:
                item.add_marker(mangled)


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
