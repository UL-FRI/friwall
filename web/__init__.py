import os
import syslog
import secrets

import flask
import flask_login

def create_app(test_config=None):
    app = flask.Flask(__name__)
    syslog.openlog('friwall')

    # Ensure all required keys exist.
    settings = {
        'secret_key': secrets.token_hex(),
        'ldap_host': '',
        'ldap_user': '',
        'ldap_pass': '',
        'ldap_base_dn': '',
        'user_group': '',
        'oidc_server': '',
        'oidc_client_id': '',
        'oidc_client_secret': '',
        'admin_group': '',
        'admin_mail': '',
        'wg_endpoint': '',
        'wg_port': '51820',
        'wg_allowed_nets': '',
        'wg_dns': False,
        'wg_key': '',
        'wg_net': '',
        'version': 0,
    }

    from . import db
    with db.locked():
        settings |= db.read('settings')
        db.write('settings', settings)

    app.config['SECRET_KEY'] = settings.get('secret_key', '')

    from . import auth
    auth.init_app(app, settings)

    from . import errors
    errors.init_app(app)

    from . import system
    system.init_app(app)

    from . import config
    app.register_blueprint(config.blueprint)

    from . import ipsets
    app.register_blueprint(ipsets.blueprint)

    from . import nat
    app.register_blueprint(nat.blueprint)

    from . import rules
    app.register_blueprint(rules.blueprint)

    from . import vpn
    app.register_blueprint(vpn.blueprint)

    @app.route('/')
    @flask_login.login_required
    def home():
        return flask.render_template('index.html')

    @app.route('/nodes')
    @flask_login.login_required
    def nodes():
        if not flask_login.current_user.is_admin:
            return flask.Response('forbidden', status=403, mimetype='text/plain')
        with db.locked('nodes'):
            version = db.load('settings').get('version')
            nodes = db.read('nodes')
        return flask.render_template('nodes.html', version=version, nodes=nodes)

    return app
