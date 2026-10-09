"""Keep the current entry points navigable and canonical ownership visible."""
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]


class PublicLayout(unittest.TestCase):
    def test_tls_consumers_use_the_owned_crate_directly(self):
        self.assertFalse((ROOT / 'src/tls').exists())
        self.assertTrue((ROOT / 'src/quic/imp/crypto_buffer.rs').is_file())
        for path in (ROOT / 'src').rglob('*.rs'):
            self.assertNotIn('crate::tls::', path.read_text(), str(path))

    def test_http3_cli_uses_public_host_implementation(self):
        source = (ROOT / 'host/src/bin/hq.rs').read_text()
        self.assertIn('use hibana_quic_host::http3 as http3_files;', source)
        self.assertFalse((ROOT / 'host/src/bin/support/http3_files.rs').exists())
        for name in ('global', 'mod'):
            self.assertTrue((ROOT / f'host/src/http3/{name}.rs').is_file())
        wire = (ROOT / 'host/src/http3/imp/wire.rs').read_text()
        for hidden_progress in ('.send::<', '.recv::<', '.offer('):
            self.assertNotIn(hidden_progress, wire)

    def test_choreography_is_the_application_entry(self):
        base = ROOT / 'src/quic'
        self.assertTrue((base / 'global.rs').is_file())
        self.assertIn('pub async fn handshake', (base / 'local/mod.rs').read_text())
        self.assertTrue((base / 'application/global.rs').is_file())
        self.assertTrue((base / 'application/local/mod.rs').is_file())
        self.assertFalse((base / 'application/assembly').exists())
        self.assertFalse((base / 'application_stream.rs').exists())
        self.assertNotIn('pub use application::imp::stream', (base / 'mod.rs').read_text())
        for path in (base / 'application/imp/stream').glob('*.rs'):
            if path.name == 'tests.rs':
                continue
            for hidden_progress in ('.send::<', '.recv::<', '.offer('):
                self.assertNotIn(hidden_progress, path.read_text(), str(path))

    def test_each_protocol_has_adjacent_order_execution_and_parts(self):
        for domain in ('', 'application', 'early_data', 'ecn', 'path', 'retry'):
            base = ROOT / 'src/quic' / domain
            for relative in ('global.rs', 'local/mod.rs', 'imp/mod.rs'):
                self.assertTrue((base / relative).is_file(), str(base / relative))
        for path in (ROOT / 'src/quic').rglob('*.rs'):
            if 'imp' not in path.parts or path.name.endswith('tests.rs'):
                continue
            production = path.read_text().split('#[cfg(test)]')[0]
            for operation in ('.send::<', '.recv::<', '.offer('):
                self.assertNotIn(operation, production, str(path))

    def test_user_entries_do_not_depend_on_development_reports(self):
        self.assertFalse(list(ROOT.glob('CI-*.md')))
        self.assertFalse((ROOT / 'docs/WORKING-STATUS.md').exists())
        self.assertTrue((ROOT / 'examples/http3-transfer.sh').is_file())
        self.assertTrue((ROOT / 'examples/response_body.rs').is_file())

    def test_host_handshake_is_reusable_without_cli(self):
        cli = (ROOT / 'host/src/bin/support/direct_bootstrap.rs').read_text()
        self.assertIn('pub use hibana_quic_host::connection::handshake;', cli)
        self.assertNotIn('pub async fn handshake', cli)
        local = (ROOT / 'host/src/connection/local/mod.rs').read_text()
        self.assertIn('Roles::attach', local)
        self.assertIn('quic::handshake(', local)

    def test_current_landing_links_resolve(self):
        for name in ('README.md', 'host/README.md'):
            path = ROOT / name
            for link in re.findall(r'\]\(([^)]+)\)', path.read_text()):
                if '://' in link or link.startswith('#'):
                    continue
                target = (path.parent / link.split('#')[0]).resolve()
                self.assertTrue(target.exists(), f'{name}: {link}')


if __name__ == '__main__':
    unittest.main()
