#!/usr/bin/python3

import collections
import email.message
import getpass
import multiprocessing
import os
import pathlib
import shutil
import smtplib
import socket
import subprocess
import sys
import syslog

import click
import flask
import flask.cli
import ldap3

from . import db

def mail(rcpt, subject, body):
    try:
        msg = email.message.EmailMessage()
        msg['Subject'] = f'friwall: {subject}'
        msg['From'] = f'{getpass.getuser()}@{socket.getfqdn()}'
        msg['To'] = rcpt
        msg.set_content(body)
        with smtplib.SMTP('localhost') as server:
            server.send_message(msg)
    except Exception as e:
        syslog.syslog(f'error sending mail: {e}')

def init_app(app):
    app.cli.add_command(generate)
    app.cli.add_command(push)

def run(fun, args=()):
    def task():
        if os.fork() == 0:
            os.setsid()
            fun(*args)
    multiprocessing.Process(target=task).start()

# For a network named 'xyzzy-foo', return xyzzy. Used for creating
# ipsets for office-* and server-* networks.
def network_group(name):
    match name.split('-'):
        case group, _:
            return group
        case _:
            return None

def ipset_add(ipsets, name, ip=None, ip6=None):
    ipsets[name].update(ip or ())
    ipsets[f'{name}/6'].update(ip6 or ())

def save_config():
    output = None
    try:
        # Just load the settings here but keep the database unlocked
        # while we load group memberships from LDAP.
        with db.locked():
            settings = db.read('settings')
            groups = db.read('groups')

        # For each user build a list of networks they have access to, based on
        # group membership in AD. Only query groups associated with at least one
        # network, and query each group only once.
        user_networks = collections.defaultdict(set)
        ldap = ldap3.Connection(ldap3.Server(settings.get('ldap_host'), use_ssl=True),
                settings.get('ldap_user'), settings.get('ldap_pass'), auto_bind=True)
        ldap.search(settings.get('ldap_base_dn', ''),
                    '(&(objectClass=user)(objectCategory=person)' + # only people
                    '(!(userAccountControl:1.2.840.113556.1.4.803:=2))' + # with enabled accounts
                    f'(memberOf:1.2.840.113556.1.4.1941:={settings.get("user_group", "")}))', # in given group, recursively
                    attributes=['userPrincipalName', 'memberOf'])
        for entry in ldap.entries:
            for group in entry.memberOf:
                if group in groups:
                    user_networks[entry.userPrincipalName.value].add(groups[group])

        # Now read the settings again and lock the database while generating
        # config files, then increment version before unlocking.
        with db.locked():
            settings = db.read('settings')
            version = settings['version'] = int(settings.get('version', 0)) + 1

            # Populate IP sets.
            ipsets = collections.defaultdict(set)
            for name, network in db.read('networks').items():
                if group := network_group(name):
                    ipset_add(ipsets, group, network.get('ip'), network.get('ip6'))
                ipset_add(ipsets, name, network.get('ip'), network.get('ip6'))

            for name, network in db.read('ipsets').items():
                ipset_add(ipsets, name, network.get('ip'), network.get('ip6'))

            # Add registered VPN addresses for each network based on
            # LDAP group membership.
            wireguard = db.read('wireguard')
            for ip, key in wireguard.items():
                ip4 = [f'{ip}/32']
                ip6 = [f'{key["ip6"]}/128'] if key.get('ip6') else None
                for network in user_networks.get(key.get('user', ''), ()):
                    if group := network_group(network):
                        ipset_add(ipsets, group, ip4, ip6)
                    ipset_add(ipsets, network, ip4, ip6)

            # Create config files.
            output = pathlib.Path.home() / 'config' / f'{version}'
            shutil.rmtree(output, ignore_errors=True)
            os.makedirs(f'{output}/etc/nftables.d', exist_ok=True)
            os.makedirs(f'{output}/etc/wireguard', exist_ok=True)

            # Print version.
            with open(f'{output}/version', 'w', encoding='utf-8') as f:
                print(version, file=f)

            # Print nftables sets.
            with open(f'{output}/etc/nftables.d/sets.nft', 'w', encoding='utf-8') as f:
                def format_set(name, ips):
                    return f'''\
set {name} {{
    type {"ipv6_addr" if name.endswith('/6') else "ipv4_addr"}; flags interval
    {"" if ips else "# "}elements = {{ {", ".join(ips)} }}
}}'''
                for name, ips in ipsets.items():
                    print(format_set(name, ips), file=f)

            # Print static NAT (1:1) rules.
            with open(f'{output}/etc/nftables.d/netmap.nft', 'w', encoding='utf-8') as f:
                def format_map(name, elements):
                    lines = ',\n'.join(f'{a}: {b}' for a, b in elements)
                    return f'''\
map {name} {{
    type ipv4_addr : interval ipv4_addr; flags interval
    elements = {{ {lines} }}
}}
'''
                netmap = db.read('netmap') # { private range: public range… }
                if netmap:
                    print(format_map('netmap-out', ((private, public) for private, public in netmap.items())), file=f)
                    print(format_map('netmap-in', ((public, private) for private, public in netmap.items())), file=f)

            # Print dynamic NAT rules.
            with open(f'{output}/etc/nftables.d/nat.nft', 'w', encoding='utf-8') as f:
                nat = db.read('nat') # { network name: public range… }
                for network, address in nat.items():
                    if address:
                        print(f'iif @inside oif @outside ip saddr @{network} snat to {address}', file=f)

            # Print forwarding rules.
            with open(f'{output}/etc/nftables.d/forward.nft', 'w', encoding='utf-8') as f:
                for index, rule in enumerate(db.read('rules')):
                    if rule.get('enabled') and rule.get('text'):
                        if 'name' in rule:
                            print(f'# {index}. {rule["name"]}', file=f)
                            print(rule['text'], file=f)
                            print(file=f)

            # Print wireguard config.
            with open(f'{output}/etc/wireguard/wg.conf', 'w', encoding='utf-8') as f:
                print(f'''\
[Interface]
ListenPort = {settings.get('wg_port', 51820)}
PrivateKey = {settings.get('wg_key')}
''', file=f)
                for ip, data in wireguard.items():
                    print(f'''\
# {data.get('user')}
[Peer]
PublicKey = {data.get('key')}
AllowedIPs = {ip}
''', file=f)
                    if 'ip6' in data:
                        print(f'AllowedIPs = {data["ip6"]}', file=f)

            # Make a config archive in a temporary place, so we don’t send
            # incomplete tars.
            tar_file = shutil.make_archive(f'{output}-tmp', 'gztar', root_dir=output, owner='root', group='root')

            # Move config archive to the final destination.
            os.rename(tar_file, f'{output}.tar.gz')

            # If we get here, write settings with the new version.
            db.write('settings', settings)
            return True

    except Exception as e:
        import traceback
        e.add_note(f'exception while generating config: {e}')
        msg = traceback.format_exc()
        if rcpt := settings.get('admin_mail'):
            mail(rcpt, 'error generating config', msg)
        # TODO this doesn’t seem to work
        #syslog.syslog(msg)
        return False

    finally:
        # Remove temporary directory.
        if output:
            shutil.rmtree(output, ignore_errors=True)

@click.command('generate')
@flask.cli.with_appcontext
def generate():
    save_config()

@click.command('push')
@click.option('--version', '-v', type=click.INT, default=None, help="Config version to push")
@flask.cli.with_appcontext
def push(version=None):
    try:
        with db.locked('nodes'):
            if version is None:
                version = db.load('settings').get('version', 0)

            nodes = db.read('nodes')
            tar_file = pathlib.Path.home() / 'config' / f'{version}.tar.gz'

            errors = []
            for node, node_version in nodes.items():
                if node_version != version:
                    try:
                        # Push config tarfile to node. There sshd runs a forced command that
                        # reads in a tarball, copies files to /etc and reloads services.
                        syslog.syslog(f'updating config for {node} from v{node_version} to v{version}')
                        result = subprocess.run(['/usr/bin/ssh', '-T', '-o', 'ConnectTimeout=10', f'root@{node}'],
                                                stdin=open(tar_file), capture_output=True, text=True)
                        if result.returncode == 0:
                            nodes[node] = version
                            db.write('nodes', nodes)
                            syslog.syslog(f'successfully updated config for {node} to v{version}')
                        else:
                            raise RuntimeError(f'error updating config to v{version}: {result.stderr}')
                    except (FileNotFoundError, RuntimeError) as e:
                        e.add_note(f'error while updating node {node}')
                        errors.append(e)
            if errors:
                raise ExceptionGroup('errors while updating nodes', errors)

    except Exception as e:
        import traceback
        msg = traceback.format_exc()
        if rcpt := db.load('settings').get('admin_mail'):
            mail(rcpt, 'error updating nodes', msg)
        syslog.syslog(msg)

