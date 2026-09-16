"""Provider egress for a reviewed bwrap command, never the host firewall.

Exact names are resolved once before launch; only their public IPv4 TCP/443
destinations are allowed. This is an IP/port boundary, not an HTTP content filter.
"""
import hashlib
import ipaddress
import os
from pathlib import Path
import socket

ROOT = Path(__file__).resolve().parents[1]
DEPS = ROOT / '.network-deps/root'
WORKER = ROOT / 'harness/network_worker.py'
AGY_HOSTS = ('accounts.google.com', 'oauth2.googleapis.com',
             'www.googleapis.com', 'antigravity.google',
             'daily-cloudcode-pa.googleapis.com')
CODEX_HOSTS = ('chatgpt.com', 'auth.openai.com')
# Opt-in startup review only. Never selected by the application or default agy probe.
AGY_PROFILE_HOSTS = (*AGY_HOSTS, 'lh3.googleusercontent.com')


def hosts_for(provider):
    if provider == 'agy':
        return AGY_HOSTS
    if provider == 'codex':
        return CODEX_HOSTS
    if provider == 'agy-profile-review':
        return AGY_PROFILE_HOSTS
    raise ValueError('unsupported_network_provider')

PINNED_FILES = {
    'usr/bin/slirp4netns': '3921b699568c75c65457326e6d3511b2be6f6cbd503bc85bff2bd852d63fbf46',
    'usr/sbin/nft': '3f1c21553e62716ef1abfcf31f51ff94eb73ff4234a6653bac754a42f936d1c7',
    'usr/lib/x86_64-linux-gnu/libslirp.so.0.4.0': '1f71a24af59f3aa76c1e0bcf7852de08c1c21c40524479b9d5df404d903b2280',
    'usr/lib/x86_64-linux-gnu/libnftables.so.1.1.0': '992de9571a44b904f0f55626160bdd60b690227cbffb8b7f962b0950e22bead3',
    'usr/lib/x86_64-linux-gnu/libnftnl.so.11.6.0': '31de1bbd42e0976d6fbde5cc8b805036189506d092dd0964dc8547b2e2ad57e5',
}
LIBRARY_ALIASES = {'libslirp.so.0': 'libslirp.so.0.4.0',
                   'libnftables.so.1': 'libnftables.so.1.1.0',
                   'libnftnl.so.11': 'libnftnl.so.11.6.0'}


def dependencies_verified():
    try:
        lib = DEPS / 'usr/lib/x86_64-linux-gnu'
        return (all(hashlib.sha256((DEPS / p).read_bytes()).hexdigest() == digest
                    for p, digest in PINNED_FILES.items()) and
                all((lib / alias).resolve() == lib / target
                    for alias, target in LIBRARY_ALIASES.items()))
    except OSError:
        return False


def public_ipv4(values):
    if not isinstance(values, list) or not 1 <= len(values) <= 64:
        raise ValueError('invalid_destination_count')
    for value in values:
        ip = ipaddress.ip_address(value)
        if (not isinstance(value, str) or ip.version != 4 or not ip.is_global
                or ip.is_multicast or ip.is_reserved or str(ip) != value):
            raise ValueError('non_public_destination')
    return sorted(set(values))


def resolve_google():
    return resolve_hosts('agy')


def resolve_hosts(provider):
    # This trusted setup DNS lookup is outside the CLI namespace. No user names,
    # search suffixes, prompt data, API keys or credentials enter the resolver.
    return {host: public_ipv4([item[4][0] for item in socket.getaddrinfo(
        host + '.', 443, socket.AF_INET, socket.SOCK_STREAM)]) for host in hosts_for(provider)}


def rules_for(addresses):
    members = ', '.join(public_ipv4(addresses))
    return ('table inet union_egress {\n'
            f' set destinations4 {{ type ipv4_addr; elements = {{ {members} }}; }}\n'
            ' chain output { type filter hook output priority 0; policy drop;\n'
            '  oifname "lo" accept; ip daddr @destinations4 tcp dport 443 accept; counter; }\n'
            ' chain input { type filter hook input priority 0; policy drop;\n'
            '  iifname "lo" accept; ip saddr @destinations4 tcp sport 443 accept; counter; }\n'
            ' chain forward { type filter hook forward priority 0; policy drop; }\n}\n')


def guarded_command(command, fixture_root, *, provider='agy'):
    hosts_for(provider)
    # Only trusted harness code supplies argv; no endpoint/option web API exists.
    if (not command or command[0] != '/usr/bin/bwrap' or '--unshare-all' not in command
            or '--share-net' in command or '--netns' in command):
        raise ValueError('isolated_bwrap_required')
    if not dependencies_verified():
        raise ValueError('network_dependencies_unverified')
    root = Path(fixture_root)
    if root.is_symlink() or not root.is_dir() or not (root / 'etc/hosts').is_file():
        raise ValueError('invalid_network_fixture')
    # The firewall parent maps itself to root to administer its private netns.
    # Preserve the host caller's numeric identity in the nested CLI userns;
    # otherwise Codex sees uid 0 and attempts a different sandbox setup.
    command = [command[0], '--uid', str(os.getuid()), '--gid', str(os.getgid()), *command[1:]]
    return ['/usr/bin/python3', '-I', str(WORKER), '--provider', provider, str(root),
            os.readlink('/proc/self/ns/net'), '--', *command]
