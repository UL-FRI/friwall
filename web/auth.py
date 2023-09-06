import authlib.integrations.flask_client
import flask
import flask_login
import urllib.parse

from . import db

login_manager = None
auth = None
users = {}

class User(flask_login.UserMixin):
    def __init__(self, userinfo):
        self.username = userinfo['preferred_username']
        self.groups = set(userinfo.get('groups', ()))
        self.data = userinfo
        try:
            self.is_admin = db.load('settings').get('admin_group') in self.groups
        except:
            self.is_admin = False

    def __repr__(self):
        return f'{self.username} {self.groups}'

    def get_id(self):
        return self.username

def init_app(app):
    settings = db.load('settings')
    login_manager = flask_login.LoginManager(app)
    oauth = authlib.integrations.flask_client.OAuth(app)
    oauth.register(
        name='azure',
        server_metadata_url=f'https://login.microsoftonline.com/{settings.get("oidc_tenant")}/v2.0/.well-known/openid-configuration',
        client_id=settings.get('oidc_client_id'),
        client_secret=settings.get('oidc_client_secret'),
        client_kwargs={'scope': 'openid profile email'})

    @login_manager.user_loader
    def load_user(username):
        return users.get(username)

    @login_manager.unauthorized_handler
    def unauth_handler():
        return flask.redirect(flask.url_for('login', next=flask.request.endpoint))

    @app.route('/login')
    def login():
        return oauth.azure.authorize_redirect(flask.url_for('auth', _external=True))

    @app.route('/auth')
    def auth():
        token = oauth.azure.authorize_access_token()
        user = users[user.username] = User(oauth.azure.parse_id_token(token))
        flask_login.login_user(user)
        return flask.redirect('/')

    @app.route('/logout')
    def logout():
        flask_login.logout_user()
        return flask.redirect(
            f'https://login.microsoftonline.com/common/oauth2/v2.0/logout?'
            + urllib.parse.urlencode(
                {
                    'returnTo': flask.url_for('home', _external=True),
                    'client_id': settings.get('oidc_client_id')
                },
                quote_via=urllib.parse.quote_plus))
