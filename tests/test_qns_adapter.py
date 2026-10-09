import importlib.util
from pathlib import Path
import socket
import unittest
from unittest import mock

spec = importlib.util.spec_from_file_location('qns_endpoint', Path(__file__).parents[1] / 'tests/interop/qns/endpoint.py')
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
    def test_retry_requires_server_admission_without_extra_shell_parameters(self):
        args=module.command({'ROLE':'server','TESTCASE':'retry'},resolve)
        self.assertEqual(args[args.index('--retry')+1],'required')
        env=self.env();env['TESTCASE']='retry'
        client=module.command(env,resolve)
        self.assertEqual(client[1],'client')
        self.assertNotIn('--retry',client)

    def test_ecn_uses_the_same_real_endpoint_without_extra_marking_flags(self):
        for role in ('client', 'server'):
            env = self.env(); env.update(ROLE=role, TESTCASE='ecn')
            actual = module.command(env, resolve)
            env['TESTCASE'] = 'transfer'
            self.assertEqual(actual, module.command(env, resolve))

    def test_server_real_chain_and_files(self):
        args = module.command({'ROLE':'server', 'TESTCASE':'handshake'}, resolve)
        self.assertIn('/certs/priv.key', args)
        self.assertIn('/www', args)
    def test_chacha_requires_explicit_policy_on_both_roles(self):
        for role in ('client','server'):
            env=self.env();env.update(ROLE=role, TESTCASE='chacha20')
            args=module.command(env,resolve)
            self.assertEqual(args[args.index('--cipher')+1], 'chacha20')
        self.assertNotIn('--cipher',module.command(self.env(),resolve))

    def test_resumption_uses_two_connections_without_fabricating_keylogs(self):
        for role in ('client', 'server'):
            env = self.env(); env.update(ROLE=role, TESTCASE='resumption')
            args = module.command(env, resolve)
            self.assertEqual(args[args.index('--session') + 1], 'resume')
            self.assertNotIn('--early', args)
        env = self.env(); env.update(TESTCASE='resumption', REQUESTS='https://server/a')
        with self.assertRaises(ValueError):
            module.command(env, resolve)
        self.assertNotIn('--session', module.command(self.env(), resolve))

    def test_zerortt_explicit_replay_safe_client_and_buffered_server(self):
        args = module.command({'ROLE':'server', 'TESTCASE':'zerortt'}, resolve)
        self.assertEqual(args[args.index('--session') + 1], 'resume')
        self.assertEqual(args[args.index('--early') + 1], 'buffered')
        env = self.env(); env.update(TESTCASE='zerortt', REQUESTS='https://server/a https://server/b')
        args = module.command(env, resolve)
        self.assertEqual(args[args.index('--early') + 1], 'replay-safe')
        self.assertEqual(args[args.index('--session') + 1], 'resume')
        env['REQUESTS'] = 'https://server/a'
        with self.assertRaises(ValueError):
            module.command(env, resolve)

    def test_keyupdate_client_requests_one_actual_generation(self):
        env = self.env(); env.update(TESTCASE='keyupdate')
        args = module.command(env, resolve)
        self.assertEqual(args[args.index('--key-update') + 1], 'once')
        args = module.command({'ROLE':'server', 'TESTCASE':'keyupdate'}, resolve)
        self.assertNotIn('--key-update', args)

    def test_multiconnect_uses_independent_bounded_connections(self):
        for role in ('client', 'server'):
            env = self.env(); env.update(ROLE=role, TESTCASE='multiconnect')
            args = module.command(env, resolve)
            self.assertEqual(args[args.index('--session') + 1], 'multi')
            self.assertEqual(args[args.index('--timeout-seconds') + 1], '300')
            self.assertNotIn('--early', args)
            if role == 'server':
                self.assertEqual(args[args.index('--connections') + 1], '50')
            else:
                self.assertNotIn('--connections', args)
                self.assertEqual(args.count('--request'), 2)

    def test_http3_selects_explicit_alpn_policy_in_both_roles(self):
        for role in ('client', 'server'):
            env = self.env(); env.update(ROLE=role, TESTCASE='http3')
            args = module.command(env, resolve)
            self.assertEqual(args[args.index('--http') + 1], '3')
            self.assertNotIn('--session', args)

    def test_unsupported_is_explicit(self):
        for case in ('unknown', 'unimplemented-extension'):
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
