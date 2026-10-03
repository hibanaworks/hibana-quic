#!/usr/bin/env python3
"""Real process/UDP evidence for the direct authenticated TLS prefix only."""
import argparse
import json
import pathlib
import selectors
import subprocess
import tempfile

def checked(args, directory):
    subprocess.run(args, cwd=directory, check=True, stdout=subprocess.DEVNULL,
                   stderr=subprocess.PIPE, timeout=20)

def credentials(directory):
    checked(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
             "-nodes", "-days", "2", "-subj", "/CN=direct Hibana ephemeral test CA",
             "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign,cRLSign",
             "-keyout", "ca.key", "-out", "ca.pem"], directory)
    checked(["openssl", "req", "-new", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
             "-nodes", "-subj", "/CN=localhost", "-keyout", "server.key", "-out", "server.csr"], directory)
    (directory / "extensions.cnf").write_text("basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:localhost\n")
    checked(["openssl", "x509", "-req", "-in", "server.csr", "-CA", "ca.pem", "-CAkey", "ca.key",
             "-CAcreateserial", "-days", "2", "-extfile", "extensions.cnf", "-out", "server.pem"], directory)
    checked(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
             "-nodes", "-days", "2", "-subj", "/CN=untrusted direct Hibana test CA", "-addext",
             "basicConstraints=critical,CA:TRUE", "-keyout", "wrong-ca.key", "-out", "wrong-ca.pem"], directory)

def scenario(binary, directory, name, bind="127.0.0.1:0", hostname="localhost", ca="ca.pem", success=True):
    timeout = "5" if success else "2"
    server = subprocess.Popen([str(binary), "server", "--listen", bind, "--cert", str(directory / "server.pem"),
                               "--key", str(directory / "server.key"), "--timeout-seconds", timeout],
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(server.stderr, selectors.EVENT_READ)
            if not selector.select(5): raise AssertionError(f"{name}: server did not become ready")
            ready = server.stderr.readline().strip()
        prefix = "direct Hibana server listening on "
        assert ready.startswith(prefix), (name, ready)
        address = ready[len(prefix):]
        client = subprocess.run([str(binary), "client", "--connect", address, "--server-name", hostname,
                                 "--ca", str(directory / ca), "--timeout-seconds", timeout],
                                capture_output=True, text=True, timeout=8)
        server_out, server_error = server.communicate(timeout=8)
        if success:
            assert client.returncode == 0, (name, client.stderr)
            assert server.returncode == 0, (name, server_error)
            reports = [json.loads(client.stdout), json.loads(server_out)]
            for report in reports:
                assert report["backend"] == "direct-hibana-roles", report
                assert report["scope"] == "authenticated-handshake-prefix", report
                assert report["tls_finished_authenticated"] and report["owned_application_continuations"], report
                assert not report["http_transfer_complete"] and not report["quic_handshake_confirmed"], report
                assert report["datagrams_sent"] > 0 and report["datagrams_received"] > 0, report
                assert report["reactor_socket_events"] > 0 and report["reactor_waits"] > 0, report
            return {"scenario": name, "passed": True, "client": reports[0], "server": reports[1]}
        assert client.returncode != 0 and server.returncode != 0, (name, client.stdout, server_out)
        assert not client.stdout and not server_out, (name, client.stdout, server_out)
        assert "Tls(" in client.stderr, (name, client.stderr)
        return {"scenario": name, "passed": True, "client_exit": client.returncode, "server_exit": server.returncode, "client_error": client.stderr.strip()}
    finally:
        if server.poll() is None: server.kill(); server.communicate()

def main():
    parser = argparse.ArgumentParser(); parser.add_argument("--binary", type=pathlib.Path, required=True); parser.add_argument("--output", type=pathlib.Path); args = parser.parse_args()
    binary = args.binary.resolve(strict=True)
    with tempfile.TemporaryDirectory(prefix="hibana-direct-udp-") as tmp:
        directory = pathlib.Path(tmp); credentials(directory)
        results = [scenario(binary, directory, "ipv4_real_udp"), scenario(binary, directory, "ipv6_real_udp", bind="[::1]:0"),
                   scenario(binary, directory, "wrong_hostname", hostname="wrong.example", success=False), scenario(binary, directory, "untrusted_ca", ca="wrong-ca.pem", success=False)]
    output = json.dumps({"scope": "authenticated-handshake-prefix", "results": results}, indent=2) + "\n"
    if args.output: args.output.write_text(output)
    print(output, end="")
if __name__ == "__main__": main()
