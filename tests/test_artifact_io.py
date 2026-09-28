import json
import stat
from pathlib import Path

import pytest

from tools import artifact_io


@pytest.mark.parametrize("payload", [{}, {"z": "证据", "a": [None, False, 0]}, []])
@pytest.mark.parametrize("options", [{}, {"sort_keys": True}, {"ensure_ascii": True}])
def test_json_publication_preserves_format_and_private_mode(tmp_path, payload, options):
    path = tmp_path / "nested" / "artifact.json"
    artifact_io.write_json_atomic(path, payload, **options)
    expected = json.dumps(payload, ensure_ascii=options.get("ensure_ascii", False),
                          indent=2, sort_keys=options.get("sort_keys", False)) + "\n"
    assert path.read_bytes() == expected.encode("utf-8")
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert list(path.parent.iterdir()) == [path]


@pytest.mark.parametrize("failure", ["write", "fsync", "replace", "interrupt", "serialize"])
def test_failed_publication_keeps_old_bytes_and_cleans_temporary(tmp_path, monkeypatch, failure):
    path = tmp_path / "artifact.json"
    original = b'{"generation": "old"}\n'
    path.write_bytes(original)

    def fail(*_args, **_kwargs):
        raise OSError("publication interrupted")

    if failure == "fsync":
        monkeypatch.setattr(artifact_io.os, "fsync", fail)
    elif failure == "replace":
        monkeypatch.setattr(Path, "replace", fail)
    exception = KeyboardInterrupt if failure == "interrupt" else TypeError if failure == "serialize" else OSError
    with pytest.raises(exception):
        if failure == "serialize":
            artifact_io.write_json_atomic(path, {"bad": object()})
        else:
            with artifact_io.atomic_text_writer(path) as handle:
                handle.write("partial")
                assert path.read_bytes() == original
                if failure == "write":
                    fail()
                elif failure == "interrupt":
                    raise KeyboardInterrupt
    assert path.read_bytes() == original
    assert list(tmp_path.iterdir()) == [path]


def test_overlapping_publishers_have_independent_temporary_files(tmp_path):
    path = tmp_path / "artifact.txt"
    with artifact_io.atomic_text_writer(path) as first:
        first.write("first")
        artifact_io.write_text_atomic(path, "second")
        assert path.read_text() == "second"
    assert path.read_text() == "first"
    artifact_io.write_text_atomic(path, "")
    assert path.read_bytes() == b""
    assert list(tmp_path.iterdir()) == [path]
