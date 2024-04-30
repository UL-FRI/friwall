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
import syslog

import click
import flask
import flask.cli
import ldap3

from . import db

def init_app(app):
    app.cli.add_command(generate)
    app.cli.add_command(push)

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

def run(fun, args=()):
    def task():
        if os.fork() == 0:
            os.setsid()
            fun(*args)
    multiprocessing.Process(target=task).start()

# Generate configuration files and create a config tarball.
def save_config():
    output = None
    try:
        # Just load required settings here but keep the database unlocked
        # while we load group memberships from LDAP.
        with db.locked():
            ipsets = db.read('ipsets')
            settings = db.read('settings')

        # Build LDAP query for users and groups.
        filters = [
            '(objectClass=user)', # only users
            '(objectCategory=person)', # that are people
            '(!(userAccountControl:1.2.840.113556.1.4.803:=2))', # with enabled accounts
        ]
        if group := settings.get('user_group'):
            filters += [f'(memberOf:1.2.840.113556.1.4.1941:={group})'] # in given group, recursively

        # Run query and store group membership data.
        server = ldap3.Server(settings['ldap_host'], use_ssl=True)
        ldap = ldap3.Connection(server, settings['ldap_user'], settings['ldap_pass'], auto_bind=True)
        ldap.search(settings.get('ldap_base_dn', ''),
                f'(&{"".join(filters)})', # conjuction (&(…)(…)(…)) of queries
                attributes=['userPrincipalName', 'memberOf'])
        user_groups = { e.userPrincipalName.value: set(e.memberOf) for e in ldap.entries }

        # Now read the settings again while keeping the database locked until
        # config files are generated, and increment version before unlocking.
        with db.locked():
            ipsets = db.read('ipsets')
            wireguard = db.read('wireguard')
            settings = db.read('settings')
            version = settings['version'] = int(settings.get('version') or '0') + 1

            # Update IP sets with VPN addresses based on AD group membership.
            vpn_groups = set([e['vpn'] for e in ipsets.values() if e.get('vpn')])
            group_networks = {
                group: [name for name, data in ipsets.items() if data['vpn'] == group] for group in vpn_groups
            }
            for ip, key in wireguard.items():
                for group in user_groups.get(key.get('user', ''), ()):
                    for network in group_networks.get(group, ()):
                        ipsets[network]['ip'].append(f'{ip}/32')
                        if ip6 := key.get('ip6'):
                            ipsets[network]['ip6'].append(ip6)

            # Create config files.
            output = pathlib.Path.home() / 'config' / f'{version}'
            shutil.rmtree(output, ignore_errors=True)
            os.makedirs(output / 'etc/nftables.d', exist_ok=True)
            os.makedirs(output / 'etc/wireguard', exist_ok=True)

            # Print version.
            with open(output / 'version', 'w', encoding='utf-8') as f:
                f.write(f'{version}')

            # Print nftables sets.
            with open(output / 'etc/nftables.d/sets.nft', 'w', encoding='utf-8') as f:
                nft_set = 'set {name} {{\n    type ipv4_addr; flags interval; {ips}\n}}\n'
                nft_set6 = 'set {name}/6 {{\n    type ipv6_addr; flags interval; {ips}\n}}\n'
                def make_set(ips):
                    # return "elements = { ip1, ip2, … }", prefixed with "# " if no ips
                    return f'{"" if ips else "# "}elements = {{ {", ".join(ips)} }}'
                for name, data in ipsets.items():
                    f.write(nft_set.format(name=name, ips=make_set(data.get('ip', ()))))
                    f.write(nft_set6.format(name=name, ips=make_set(data.get('ip6', ()))))
                    f.write('\n')

            # Print static NAT (1:1) rules.
            with open(output / 'etc/nftables.d/netmap.nft', 'w', encoding='utf-8') as f:
                nft_map = 'map {name} {{\n    type ipv4_addr : interval ipv4_addr; flags interval; elements = {{\n{ips}\n    }}\n}}\n'
                def make_map(ips, reverse=False):
                    # return "{ from1: to1, from2: to2, … }" with possibly reversed from and to
                    return ',\n'.join(f"{b if reverse else a}: {a if reverse else b}" for a, b in ips)
                if netmap := db.read('netmap'): # { private range: public range… }
                    f.write(nft_map.format(name='netmap-out', ips=make_map(netmap.items())))
                    f.write('\n')
                    f.write(nft_map.format(name='netmap-in', ips=make_map(netmap.items(), reverse=True)))

            # Print dynamic NAT rules.
            with open(output / 'etc/nftables.d/nat.nft', 'w', encoding='utf-8') as f:
                nft_nat = 'iif @inside oif @outside ip saddr @{name} snat to {nat}\n'
                for name, data in ipsets.items():
                    if nat := data.get('nat'):
                        f.write(nft_nat.format(name=name, nat=nat))

            # Print forwarding rules.
            with open(output / 'etc/nftables.d/forward.nft', 'w', encoding='utf-8') as f:
                # Forwarding rules for VPN users.
                if vpn_networks := sorted(name for name, data in ipsets.items() if data.get('vpn')):
                    nft_forward = 'iif @inside oif @inside ip saddr @{name} ip daddr @{name} accept\n'
                    f.write('# forward from the VPN interface to physical networks and back\n')
                    for name in vpn_networks:
                        f.write(nft_forward.format(name=name))
                    for name in vpn_networks:
                        f.write(nft_forward.format(name=f'{name}/6'))
                    f.write('\n')

                # Custom forwarding rules.
                nft_rule = '# {index}. {name}\n{text}\n\n'
                for index, rule in enumerate(db.read('rules')):
                    if rule.get('enabled') and rule.get('text'):
                        f.write(nft_rule.format(index=index, name=rule.get('name', ''), text=rule['text']))

            # Print wireguard config.
            with open(output / 'etc/wireguard/wg.conf', 'w', encoding='utf-8') as f:
                # Server configuration.
                wg_intf = '[Interface]\nListenPort = {port}\nPrivateKey = {key}\n\n'
                f.write(wg_intf.format(port=settings.get('wg_port') or 51820, key=settings.get('wg_key')))

                # Client configuration.
                wg_peer = '# {user}\n[Peer]\nPublicKey = {key}\nAllowedIPs = {ips}\n\n'
                for ip, data in wireguard.items():
                    f.write(wg_peer.format(
                        user=data.get('user'),
                        key=data.get('key'),
                        ips=', '.join(filter(None, [ip, data.get('ip6')]))))

            # Make a temporary config archive and move it to the final location,
            # so we avoid sending incomplete tars.
            tar_file = shutil.make_archive(f'{output}-tmp', 'gztar', root_dir=output, owner='root', group='root')
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
