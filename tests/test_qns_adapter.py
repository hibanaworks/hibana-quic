import importlib.util
from pathlib import Path
import socket
import unittest
from unittest import mock

spec = importlib.util.spec_from_file_location('qns_endpoint', Path(__file__).parents[1] / 'interop/qns/endpoint.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

def resolve(host, port, **kwargs):
    return [(socket.AF_INET, socket.SOCK_DGRAM, 17, '', ('127.0.0.1', port))]

class EndpointCommand(unittest.TestCase):
    def env(self, **extra):
        return dict(ROLE='client', TESTCASE='transfer', REQUESTS='https://server/a https://server/b', **extra)
    def test_diagnostics_are_opt_in_for_child_without_changing_arguments(self):
        env = {'ROLE':'server', 'TESTCASE':'handshake'}
        expected = module.command(env, resolve)
        with mock.patch.dict(module.os.environ, env, clear=True), \
             mock.patch.object(module.Path, 'mkdir'), \
             mock.patch('builtins.open', mock.mock_open()), \
             mock.patch.object(module.subprocess, 'run', return_value=mock.Mock(returncode=0)) as run:
            self.assertEqual(module.main(), 0)
        self.assertEqual(run.call_args.args[0], expected)
        self.assertEqual(run.call_args.kwargs['env']['HIBANA_QUIC_DIAGNOSTICS'], '1')
        self.assertEqual(run.call_args.kwargs['env']['ROLE'], 'server')
    def test_verified_origin_and_all_requests(self):
        args = module.command(self.env(), resolve)
        self.assertEqual(args.count('--request'), 2)
        self.assertEqual(args[args.index('--ca')+1], '/certs/ca.pem')
        self.assertEqual(args[args.index('--server-name')+1], 'server')
    def test_server_real_chain_and_files(self):
        args = module.command({'ROLE':'server', 'TESTCASE':'handshake'}, resolve)
        self.assertIn('/certs/priv.key', args)
        self.assertIn('/www', args)
    def test_unsupported_is_explicit(self):
        for case in ('keyupdate', 'retry', 'zerortt', 'resumption', 'http3', 'unknown'):
            with self.assertRaises(module.Unsupported):
                module.command({'ROLE':'client', 'TESTCASE':case}, resolve)
    def test_extra_params_not_evaluated(self):
        with self.assertRaises(ValueError):
            module.command(self.env(CLIENT_PARAMS='$(touch /tmp/no)'), resolve)
    def test_bad_urls_and_mixed_origins(self):
        for value in ('', 'http://server/a', 'https://user@server/a', 'https://server/a?x=1',
                      'https://server/a#x', 'https://server/a https://elsewhere/b',
                      'https://server:443/a https://server:444/b', 'https://server:bad/a'):
            env=self.env();env['REQUESTS']=value
            with self.assertRaises(ValueError): module.command(env, resolve)
    def test_ipv6_format(self):
        def v6(host, port, **kwargs):
            return [(socket.AF_INET6,socket.SOCK_DGRAM,17,'',('::1',port,0,0))]
        args=module.command(self.env(),v6)
        self.assertEqual(args[args.index('--connect')+1],'[::1]:443')
