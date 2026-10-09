"""Keep the current entry points navigable and canonical ownership visible."""
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]


class PublicLayout(unittest.TestCase):
    def test_tls_modules_are_direct_canonical_exports(self):
        source = (ROOT / 'src/tls/mod.rs').read_text()
        self.assertIn('pub use hibana_tls::{', source)
        for name in ('certificate', 'handshake', 'key_exchange', 'rsa', 'schedule', 'ticket', 'wire'):
            self.assertFalse((ROOT / f'src/tls/{name}.rs').exists())
        self.assertTrue((ROOT / 'src/tls/buffer.rs').is_file())

    def test_http3_cli_uses_public_host_implementation(self):
        source = (ROOT / 'host/src/bin/hq.rs').read_text()
        self.assertIn('use hibana_quic_host::http3 as http3_files;', source)
        self.assertFalse((ROOT / 'host/src/bin/support/http3_files.rs').exists())
        for name in ('global', 'local', 'wire', 'mod'):
            self.assertTrue((ROOT / f'host/src/http3/{name}.rs').is_file())
        wire = (ROOT / 'host/src/http3/wire.rs').read_text()
        for hidden_progress in ('.send::<', '.recv::<', '.offer('):
            self.assertNotIn(hidden_progress, wire)

    def test_current_landing_links_resolve(self):
        for name in ('README.md', 'docs/WORKING-STATUS.md', 'docs/QUALIFICATION.md',
                     'docs/APPLICATION-API.md', 'docs/GETTING-STARTED.md',
                     'docs/ACTIVE-IMPLEMENTATION.md', 'docs/ARCHITECTURE.md'):
            path = ROOT / name
            for link in re.findall(r'\]\(([^)]+)\)', path.read_text()):
                if '://' in link or link.startswith('#'):
                    continue
                target = (path.parent / link.split('#')[0]).resolve()
                self.assertTrue(target.exists(), f'{name}: {link}')


if __name__ == '__main__':
    unittest.main()
