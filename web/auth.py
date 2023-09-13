import authlib.integrations.flask_client
import flask
import flask_login
import urllib.parse

from . import db

login_manager = None
auth = None
users = {}

class User(flask_login.UserMixin):
    def __init__(self, info):
        self.username = info.get('preferred_username', '')
        self.groups = set(info.get('groups', ()))
        self.data = info # for debugging really
        try:
            self.is_admin = db.load('settings').get('admin_group') in self.groups
        except:
            self.is_admin = False

    def __repr__(self):
        return f'{self.username} {self.groups}'

    def get_id(self):
        return self.username

def init_app(app):
    login_manager = flask_login.LoginManager(app)
    oauth = authlib.integrations.flask_client.OAuth(app)
    oauth.register(
        name='default',
        server_metadata_url=app.config['OIDC_URL_DISCOVERY'],
        client_id=app.config['OIDC_CLIENT_ID'],
        client_secret=app.config['OIDC_CLIENT_SECRET'],
        client_kwargs={'scope': 'openid profile email'})

    @login_manager.user_loader
    def load_user(username):
        return users.get(username)

    @login_manager.unauthorized_handler
    def unauth_handler():
        return flask.redirect(flask.url_for('login', next=flask.request.endpoint))

    @app.route('/login')
    def login():
        return oauth.default.authorize_redirect(flask.url_for('authorize', _external=True))

    @app.route('/authorize')
    def authorize():
        token = oauth.default.authorize_access_token()
        user = users[user.username] = User(token.get('userinfo', {}))
        flask_login.login_user(user)
        return flask.redirect('/')

    @app.route('/logout')
    def logout():
        flask_login.logout_user()
        return flask.redirect(
            flask.current_app.config.get('OIDC_URL_LOGOUT') + '?'
            + urllib.parse.urlencode({'client_id': config.get('OIDC_CLIENT_ID')}))
