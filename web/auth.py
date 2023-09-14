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

def init_app(app, settings):
    login_manager = flask_login.LoginManager(app)
    oauth = authlib.integrations.flask_client.OAuth(app)
    oauth.register(
        name='default',
        server_metadata_url=settings.get('oidc_server'),
        client_id=settings.get('oidc_client_id'),
        client_secret=settings.get('oidc_client_secret'),
        client_kwargs={'scope': 'openid profile email'})

    metadata = oauth.default.load_server_metadata()
    app.config['OIDC_CLIENT_ID'] = settings.get('OIDC_CLIENT_ID')
    app.config['OIDC_END_SESSION_ENDPOINT'] = metadata.get('end_session_endpoint')

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
        if oidc_logout_url := flask.current_app.config.get('OIDC_END_SESSION_ENDPOINT'):
            return flask.redirect(oidc_logout_url + '?'
                + urllib.parse.urlencode({'client_id': flask.current_app.config.get('OIDC_CLIENT_ID')}))
        else:
            return flask.redirect('/')
