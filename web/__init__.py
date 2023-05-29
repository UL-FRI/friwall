import os
import secrets

import flask
import flask_ldap3_login
import flask_login

def create_app(test_config=None):
    app = flask.Flask(__name__)

    # Ensure all required keys exist.
    settings = {
        'debug': False,
        'secret_key': secrets.token_urlsafe(32),
        'ldap_host': '',
        'ldap_port': '636',
        'ldap_user': '',
        'ldap_pass': '',
        'ldap_admin': '',
        'ldap_base_dn': '',
        'ldap_user_dn': '',
        'ldap_login_attr': 'userPrincipalName',
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

    app.config['DEBUG'] = settings.get('debug', False)
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

    @app.route('/')
    @flask_login.login_required
    def home():
        return flask.render_template('index.html')

    return app
