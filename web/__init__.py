import os
import syslog
import secrets

import flask
import flask_ldap3_login
import flask_login

def create_app(test_config=None):
    app = flask.Flask(__name__)
    syslog.openlog('friwall')

    # Ensure all required keys exist.
    settings = {
        'secret_key': secrets.token_hex(),
        'ldap_host': '',
        'ldap_port': '636',
        'ldap_user': '',
        'ldap_pass': '',
        'ldap_admin': '',
        'ldap_base_dn': '',
        'ldap_user_dn': '',
        'ldap_login_attr': 'userPrincipalName',
        'admin_mail': '',
        'wg_endpoint': '',
        'wg_port': '51820',
        'wg_key': '',
        'wg_net': '',
        'version': 0,
    }

    from . import db
    with db.locked():
        settings |= db.read('settings')
        db.write('settings', settings)

    app.config['SECRET_KEY'] = settings.get('secret_key', '')
    app.config['LDAP_USE_SSL'] = True
    app.config['LDAP_HOST'] = settings.get('ldap_host', '')
    app.config['LDAP_PORT'] = int(settings.get('ldap_port', '636'))
    app.config['LDAP_BASE_DN'] = settings.get('ldap_base_dn', '')
    app.config['LDAP_USER_DN'] = settings.get('ldap_user_dn', '')
    app.config['LDAP_BIND_USER_DN'] = settings.get('ldap_user', '')
    app.config['LDAP_BIND_USER_PASSWORD'] = settings.get('ldap_pass', '')
    app.config['LDAP_USER_LOGIN_ATTR'] = settings.get('ldap_login_attr', 'userPrincipalName')
    app.config['LDAP_USER_SEARCH_SCOPE'] = 'SUBTREE'

    from . import auth
    app.register_blueprint(auth.blueprint)

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

    from . import system
    system.init_app(app)

    login_manager = flask_login.LoginManager(app)
    ldap_manager = flask_ldap3_login.LDAP3LoginManager(app)
    users = {}

    @login_manager.user_loader
    def load_user(id):
        return users.get(id)

    @ldap_manager.save_user
    def save_user(dn, username, data, memberships):
        user = auth.User(dn, username, data)
        users[dn] = user
        return user

    @login_manager.unauthorized_handler
    def unauth_handler():
        return flask.redirect(flask.url_for('auth.login', next=flask.request.endpoint))

    @app.errorhandler(TimeoutError)
    def timeout_error(e):
        return flask.render_template('busy.html')

    @app.errorhandler(Exception)
    def internal_server_error(e):
        return flask.Response(f'something went catastrophically wrong: {e}',
                status=500, mimetype='text/plain')

    @app.route('/')
    @flask_login.login_required
    def home():
        return flask.render_template('index.html')

    @app.route('/nodes')
    @flask_login.login_required
    def nodes():
        try:
            if not flask_login.current_user.is_admin:
                return flask.Response('forbidden', status=403, mimetype='text/plain')
            with db.locked('nodes'):
                version = db.load('settings').get('version')
                nodes = db.read('nodes')
            return flask.render_template('nodes.html', version=version, nodes=nodes)
        except TimeoutError:
            return flask.render_template('busy.html')
        except Exception as e:
            return flask.Response(f'something went catastrophically wrong: {e}',
                    status=400, mimetype='text/plain')

    return app
