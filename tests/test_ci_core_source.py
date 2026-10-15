"""Interop must qualify the fixed core in every standalone consumer."""
from contextlib import redirect_stdout
import importlib.util
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch


SOURCE = Path(__file__).resolve().parents[1]
REVISION = "0a296df98be6664f07e426c086ffbb9486be7c71"
TLS_REVISION = "6e5ece518c30a1478f75f17d23aec72b10208fd8"
REPOSITORY = "https://github.com/hibanaworks/hibana"
CORE_SOURCE = "git+" + REPOSITORY + "?rev=" + REVISION + "#" + REVISION


class CoreSource(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.folder = Path(temporary.name)
        self.root = self.folder / "hibana-quic"
        self.root.mkdir()
        tls = self.folder / "hibana-tls"
        tls.mkdir()
        (tls / "Cargo.toml").write_text('[package]\nname="hibana-tls"\n')
        (self.root / "tools/ci").mkdir(parents=True)
        (self.root / "tools/ci/pins.env").write_text("HIBANA_VERSION=0.9.9\nHIBANA_REVISION=" + REVISION + "\n")
        manifest = ('[package.metadata.hibana-source]\nrepository="' + REPOSITORY + '"\nversion="0.9.9"\nrevision="' + REVISION + '"\n'
                    '[dependencies.hibana-tls]\ngit="https://github.com/hibanaworks/hibana-tls"\nrev="' + TLS_REVISION + '"\n'
                    '[patch.crates-io.hibana]\ngit="' + REPOSITORY + '"\nrev="' + REVISION + '"\n')
        lock = '[[package]]\nname="hibana"\nversion="0.9.9"\nsource="' + CORE_SOURCE + '"\n'
        for relative in (".", "tests/interop/driver"):
            consumer = self.root / relative
            consumer.mkdir(parents=True, exist_ok=True)
            (consumer / "Cargo.toml").write_text(manifest)
            (consumer / "Cargo.lock").write_text(lock)
        spec = importlib.util.spec_from_file_location("stage_paired_source", SOURCE / "tools/ci/stage-paired-source.py")
        self.stage = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.stage)
        self.stage.ROOT = self.root
        self.output = self.folder / "staged"

    def stage_source(self):
        with patch.object(sys, "argv", ["stage-paired-source", "--output", str(self.output)]), redirect_stdout(io.StringIO()), patch.object(self.stage.subprocess, "check_output", side_effect=[TLS_REVISION, b""]):
            self.stage.main()

    def test_exact_core_revision_is_recorded(self):
        self.stage_source()
        result = json.loads((self.output / "source-pair.json").read_text())
        self.assertEqual(result["hibana_revision"], REVISION)
        self.assertEqual(result["hibana_version"], "0.9.9")
        self.assertEqual(result["tls_revision"], TLS_REVISION)

    def test_driver_cannot_fall_back_to_published_core(self):
        lock = self.root / "tests/interop/driver/Cargo.lock"
        lock.write_text(lock.read_text().replace(CORE_SOURCE, "registry+https://github.com/rust-lang/crates.io-index"))
        with self.assertRaisesRegex(AssertionError, "consumer lock selected a different core"):
            self.stage_source()
        self.assertFalse(self.output.exists())

    def test_driver_cannot_override_core_patch(self):
        manifest = self.root / "tests/interop/driver/Cargo.toml"
        manifest.write_text(manifest.read_text().replace('rev="' + REVISION + '"', 'rev="' + 'e' * 40 + '"'))
        with self.assertRaisesRegex(AssertionError, "consumer patch differs"):
            self.stage_source()
        self.assertFalse(self.output.exists())

    def test_source_pin_and_lock_must_match(self):
        pins = self.root / "tools/ci/pins.env"
        pins.write_text(pins.read_text().replace(REVISION, "e" * 40))
        with self.assertRaises(AssertionError):
            self.stage_source()
        self.assertFalse(self.output.exists())
