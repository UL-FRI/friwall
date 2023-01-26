#!/usr/bin/python3

import collections
import multiprocessing
import os
import shutil
import sqlite3
import subprocess
import sys
import syslog
import time

import click
import flask
import flask.cli
import ldap3

from . import db

def init_app(app):
    app.cli.add_command(generate)
    app.cli.add_command(push)

def run(fun, args=()):
    def task():
        if os.fork() == 0:
            os.setsid()
            fun(*args)
    multiprocessing.Process(target=task).start()

def save_config():
    output = None
    try:
        # Just load the settings here but don’t lock the database while we load
        # stuff from LDAP.
        settings = db.load('settings')
        groups = db.load('groups')

        # Get users’ group membership from LDAP server. Only query the groups used
        # by at least one network, and query each group just once.
        user_groups = collections.defaultdict(set)
        ldap = ldap3.Connection(ldap3.Server(settings.get('ldap_host'), use_ssl=True),
                settings.get('ldap_user'), settings.get('ldap_pass'), auto_bind=True)
        for group in groups:
            ldap.search(settings.get('ldap_base_dn', ''),
                        f'(distinguishedName={group})', attributes='member')
            if ldap.entries:
                for user in ldap.entries[0]['member']:
                    user_groups[user].add(group)

        # Now read the settings again and lock the database while generating
        # config files, then increment version before unlocking.
        with db.locked('settings'):
            settings = db.read('settings')
            version = settings['version'] = int(settings.get('version', 0)) + 1

            # Populate IP sets.
            wireguard = db.read('wireguard')
            ipsets = collections.defaultdict(set)
            for ip, key in wireguard.items():
                for group in user_groups.get(key.get('user', ''), ()):
                    for network in groups[group]:
                        ipsets[network].add(f'{ip}/32')

            # Create config files.
            output = f'config/{version}'
            shutil.rmtree(output, ignore_errors=True)
            os.makedirs(f'{output}/etc/nftables.d', exist_ok=True)
            os.makedirs(f'{output}/etc/wireguard', exist_ok=True)

            # Add registered VPN addresses for each network based on
            # LDAP group membership.
            with open(f'{output}/etc/nftables.d/sets-vpn.nft', 'w', encoding='utf-8') as f:
                def format_set(name, ips):
                    return f'''\
set {name} {{
    typeof ip daddr; flags interval
    elements = {{ {', '.join(ips)} }}
}}'''
                for name, networks in ipsets.items():
                    print(format_set(name, networks), file=f)

            # Print forwarding rules.
            with open(f'{output}/etc/nftables.d/forward.nft', 'w', encoding='utf-8') as f:
                def format_forward(src, dst):
                    rule = 'iifname @ifaces_inside oifname @ifaces_inside'
                    if src:
                        rule += f' ip saddr @{src}'
                    if dst:
                        rule += f' ip daddr @{dst}'
                    return rule + ' accept'
                for src, dst in db.load('forwards'):
                    print(format_forward(src, dst), file=f)

            # Print wireguard config.
            with open(f'{output}/etc/wireguard/wg.conf', 'w', encoding='utf-8') as f:
                def format_wg_peer(ip, data):
                    return f'''\
# {data.get('user')}
[Peer]
PublicKey = {data.get('key')}
AllowedIPs = {ip}
'''
                print(f'''\
[Interface]
ListenPort = {settings.get('wg_port', 51820)}
PrivateKey = {settings.get('wg_key')}
''', file=f)
                for ip, key in wireguard.items():
                    print(format_wg_peer(ip, key), file=f)

            # Make a config archive in a temporary place, so we don’t send
            # incomplete tars.
            tarfile = shutil.make_archive(f'{output}-tmp', 'gztar', root_dir=output, owner='root', group='root')

            # Move config archive to the final destination.
            os.rename(tarfile, f'{output}.tar.gz')

            # If we get here, write settings with the new version.
            db.write('settings', settings)
            return True

    except Exception as e:
        syslog.syslog(f'exception while generating config: {e}')
        import traceback
        with open('/tmp/wtflog', 'a+') as f:
            traceback.print_exc(file=f)
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
    if version is None:
        version = db.load('settings').get('version', 0)

    # Write wanted version to file for uploading to firewall nodes.
    with open('config/version', 'w') as f:
        print(version, file=f)

    try:
        with db.locked('nodes'):
            nodes = db.read('nodes')
            tarfile = f'config/{version}.tar.gz'

            done = True
            for node, node_version in nodes.items():
                if node_version != version:
                    if not os.path.exists(tarfile):
                        syslog.syslog(f'wanted to push version {version} but {version}.tar.gz doesn’t exist')
                        return

                    # Push config tarfile.
                    syslog.syslog(f'updating {node} from {node_version} to {version}')
                    result = subprocess.run([f'sftp -o ConnectTimeout=10 root@{node}'],
                                            shell=True, text=True, capture_output=True,
                                            input=f'put {tarfile}\nput config/version\n')
                    if result.returncode == 0:
                        nodes[node] = version
                        db.write('nodes', nodes)
                    else:
                        syslog.syslog(f'error updating node {node}: {result.stderr}')
                        done = False
        return done

    except Exception as e:
        import traceback
        with open('/tmp/wtflog', 'a+') as f:
            traceback.print_exc(file=f)
        return False
