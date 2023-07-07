import datetime
import ipaddress
import json
import re
import subprocess

import flask
import flask_login

from . import db
from . import system

blueprint = flask.Blueprint('vpn', __name__, url_prefix='/vpn')
wgkey_regex = re.compile(r'^[A-Za-z0-9/+=]{44}$')

@blueprint.route('/')
@flask_login.login_required
def index():
    return flask.render_template('vpn/index.html')

@blueprint.route('/list')
@flask_login.login_required
def list():
    try:
        user = flask_login.current_user.get_id()
        return flask.jsonify({k: v for k, v in db.load('wireguard').items() if v.get('user') == user})
    except TimeoutError:
        return flask.render_template('busy.html')
    except Exception as e:
        return flask.Response(f'failed: {e}', status=500, mimetype='text/plain')

@blueprint.route('/new', methods=('POST',))
@flask_login.login_required
def new():
    pubkey = flask.request.json.get('pubkey', '')
    if not re.match(wgkey_regex, pubkey):
        return flask.Response('invalid key', status=400, mimetype='text/plain')

    try:
        settings = db.load('settings')
        server_pubkey = subprocess.run([f'wg pubkey'], input=settings.get('wg_key'),
                text=True, capture_output=True, shell=True).stdout.strip()

        host = ipaddress.ip_interface(settings.get('wg_net', '10.0.0.1/24'))
        with db.locked():
            # Find a free address for the new key.
            ips = db.read('wireguard')
            for ip in host.network.hosts():
                if ip != host.ip and str(ip) not in ips:
                    break
            else:
                return flask.Response('no more available IP addresses', status=500, mimetype='text/plain')
            now = datetime.datetime.utcnow()
            name = re.sub('[^\w ]', '', flask.request.json.get('name', ''))

            ips[str(ip)] = {
                'key': pubkey,
                'time': now.timestamp(),
                'user': flask_login.current_user.get_id(),
                'name': name,
            }
            db.write('wireguard', ips)

        # Generate a new config archive for firewall nodes.
        system.run(system.save_config)

        # Template arguments.
        args = {
            'server': f'{settings.get("wg_endpoint")}',
            'port': f'{settings.get("wg_port", 51820)}',
            'server_key': server_pubkey,
            'pubkey': pubkey,
            'ip': str(ip),
            'timestamp': now,
            'name': name,
            'add_default': flask.request.json.get('add_default', False),
            'use_dns': flask.request.json.get('use_dns', True),
        }
        return flask.render_template('vpn/wg-fri.conf', **args)
    except TimeoutError:
        return flask.render_template('busy.html')
    except Exception as e:
        return flask.Response(f'something went catastrophically wrong: {e}',
                status=400, mimetype='text/plain')

@blueprint.route('/del', methods=('POST',))
@flask_login.login_required
def delete():
    pubkey = flask.request.json.get('pubkey', '')
    if not wgkey_regex.match(pubkey):
        return flask.Response('invalid key', status=400, mimetype='text/plain')

    try:
        with db.locked():
            user = flask_login.current_user.get_id()
            ips = {k: v for k, v in db.read('wireguard').items() if v.get('user') != user or v.get('key') != pubkey}
            db.write('wireguard', ips)

        system.run(system.save_config)

        return flask.Response(f'deleted key {pubkey}', status=200, mimetype='text/plain')
    except TimeoutError:
        return flask.render_template('busy.html')
    except Exception as e:
        return flask.Response(f'something went catastrophically wrong: {e}',
                status=400, mimetype='text/plain')
