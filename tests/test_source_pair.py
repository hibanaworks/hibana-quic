"""Wrong or modified sibling TLS must never enter a candidate build context."""
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


SCRIPT = Path(__file__).resolve().parents[1] / 'tools/ci/stage-paired-source.py'
CORE_REPOSITORY = 'https://github.com/hibanaworks/hibana'
CORE_REVISION = '1' * 40


class SourcePair(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.quic = self.root / 'hibana-quic'
        self.tls = self.root / 'hibana-tls'
        (self.quic / 'tools/ci').mkdir(parents=True)
        self.tls.mkdir()
        shutil.copyfile(SCRIPT, self.quic / 'tools/ci/stage-paired-source.py')
        (self.tls / 'Cargo.toml').write_text('[package]\nname = "hibana-tls"\n')
        self.git('init', '-q')
        self.git('add', '.')
        self.git('-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.test',
                 'commit', '-qm', 'Synthetic TLS source')
        self.revision = self.git('rev-parse', 'HEAD').stdout.strip()
        (self.quic / 'Cargo.lock').write_text(
            'version = 4\n\n[[package]]\nname = "hibana"\nversion = "0.0.1"\n'
            f'source = "git+{CORE_REPOSITORY}?rev={CORE_REVISION}#{CORE_REVISION}"\n')
        (self.quic / 'tools/ci/pins.env').write_text(
            f'HIBANA_VERSION=0.0.1\nHIBANA_REVISION={CORE_REVISION}\n')
        self.manifest(self.revision)
        driver = self.quic / 'tests/interop/driver'
        driver.mkdir(parents=True)
        for name in ('Cargo.toml', 'Cargo.lock'):
            shutil.copyfile(self.quic / name, driver / name)

    def git(self, *args):
        return subprocess.run(['git', '-C', str(self.tls), *args], check=True,
                              text=True, capture_output=True)

    def manifest(self, revision):
        (self.quic / 'Cargo.toml').write_text(
            '[package.metadata.hibana-source]\nversion = "0.0.1"\n'
            f'repository = "{CORE_REPOSITORY}"\nrevision = "{CORE_REVISION}"\n\n'
            '[patch.crates-io]\n'
            f'hibana = {{ git = "{CORE_REPOSITORY}", rev = "{CORE_REVISION}" }}\n\n'
            '[dependencies]\nhibana-tls = { git = "https://github.com/hibanaworks/hibana-tls", '
            f'rev = "{revision}" }}\n')

    def stage(self):
        return subprocess.run([sys.executable, str(self.quic / 'tools/ci/stage-paired-source.py'),
                               '--output', str(self.root / 'output')], text=True, capture_output=True)

    def test_exact_clean_source_is_recorded_in_a_bounded_public_identity(self):
        result = self.stage()
        self.assertEqual(result.returncode, 0, result.stderr)
        identity = self.root / 'output/source-pair.json'
        self.assertLess(identity.stat().st_size, 16384)
        pair = json.loads(identity.read_text())
        self.assertEqual(pair['tls_revision'], self.revision)
        self.assertEqual(pair['hibana_version'], '0.0.1')
        self.assertEqual(pair['hibana_revision'], CORE_REVISION)
        self.assertEqual(set(pair['trees']), {'hibana-quic', 'hibana-tls'})
        self.assertFalse((self.root / 'output/hibana-tls/.git').exists())
        committed = self.git('show', 'HEAD:Cargo.toml').stdout.encode()
        self.assertEqual((self.root / 'output/hibana-tls/Cargo.toml').read_bytes(), committed)
        files = json.loads((self.root / 'output/source-files.json').read_text())
        self.assertEqual(files['hibana-tls/Cargo.toml'], hashlib.sha256(committed).hexdigest())
        for relative in ('Cargo.lock', 'tests/interop/driver/Cargo.lock'):
            self.assertEqual((self.root / 'output/hibana-quic' / relative).read_bytes(),
                             (self.quic / relative).read_bytes())

    def test_wrong_commit_is_rejected(self):
        self.manifest('0' * 40)
        result = self.stage()
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.root / 'output').exists())

    def test_modified_or_untracked_tls_is_rejected(self):
        for name in ('Cargo.toml', 'extra.rs'):
            with self.subTest(name=name):
                path = self.tls / name
                original = path.read_text() if path.exists() else None
                path.write_text('unexpected source\n')
                result = self.stage()
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse((self.root / 'output').exists())
                if original is None:
                    path.unlink()
                else:
                    path.write_text(original)

    def test_missing_tls_cannot_be_substituted(self):
        shutil.rmtree(self.tls)
        self.assertNotEqual(self.stage().returncode, 0)
        self.assertFalse((self.root / 'output').exists())

    def test_mismatched_core_inputs_cannot_produce_a_source_export(self):
        source = f'git+{CORE_REPOSITORY}?rev={CORE_REVISION}#{CORE_REVISION}'
        for relative, before, after in (
            ('Cargo.lock', CORE_REVISION, '2' * 40),
            ('tools/ci/pins.env', CORE_REVISION, '2' * 40),
            ('tests/interop/driver/Cargo.lock', source,
             'registry+https://github.com/rust-lang/crates.io-index'),
            ('tests/interop/driver/Cargo.toml', f'rev = "{CORE_REVISION}"',
             f'rev = "{"2" * 40}"'),
        ):
            with self.subTest(input=relative):
                path = self.quic / relative
                original = path.read_text()
                path.write_text(original.replace(before, after))
                result = self.stage()
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse((self.root / 'output').exists())
                path.write_text(original)
