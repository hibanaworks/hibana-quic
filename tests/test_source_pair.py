"""Wrong or modified sibling TLS must never enter a candidate build context."""
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


SCRIPT = Path(__file__).resolve().parents[1] / 'tools/ci/stage-paired-source.py'


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
        self.manifest(self.revision)

    def git(self, *args):
        return subprocess.run(['git', '-C', str(self.tls), *args], check=True,
                              text=True, capture_output=True)

    def manifest(self, revision):
        (self.quic / 'Cargo.toml').write_text(
            '[dependencies]\nhibana-tls = { git = "https://github.com/hibanaworks/hibana-tls", '
            f'rev = "{revision}" }}\n')

    def stage(self):
        return subprocess.run([sys.executable, str(self.quic / 'tools/ci/stage-paired-source.py'),
                               '--output', str(self.root / 'output')], text=True, capture_output=True)

    def test_exact_clean_source_is_recorded_in_a_bounded_public_identity(self):
        self.assertEqual(self.stage().returncode, 0)
        identity = self.root / 'output/source-pair.json'
        self.assertLess(identity.stat().st_size, 16384)
        pair = json.loads(identity.read_text())
        self.assertEqual(pair['tls_revision'], self.revision)
        self.assertEqual(set(pair['trees']), {'hibana-quic', 'hibana-tls'})
        self.assertFalse((self.root / 'output/hibana-tls/.git').exists())

    def test_wrong_commit_is_rejected(self):
        self.manifest('0' * 40)
        self.assertNotEqual(self.stage().returncode, 0)

    def test_modified_or_untracked_tls_is_rejected(self):
        for name in ('Cargo.toml', 'extra.rs'):
            with self.subTest(name=name):
                path = self.tls / name
                original = path.read_text() if path.exists() else None
                path.write_text('unexpected source\n')
                self.assertNotEqual(self.stage().returncode, 0)
                if original is None:
                    path.unlink()
                else:
                    path.write_text(original)

    def test_missing_tls_cannot_be_substituted(self):
        shutil.rmtree(self.tls)
        self.assertNotEqual(self.stage().returncode, 0)
