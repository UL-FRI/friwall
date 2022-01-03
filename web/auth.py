import flask
import flask_login
import flask_ldap3_login.forms

from . import db

blueprint = flask.Blueprint('auth', __name__, url_prefix='/auth')

class User(flask_login.UserMixin):
    def __init__(self, dn, username, data):
        self.dn = dn
        self.username = username
        self.data = data
        self.groups = data.get('memberOf', [])
        try:
            self.is_admin = db.load('settings').get('ldap_admin') in self.groups
        except:
            self.is_admin = False

    def __repr__(self):
        return self.dn

    def get_id(self):
        return self.dn

@blueprint.route('/login', methods=['GET', 'POST'])
def login():
    form = flask_ldap3_login.forms.LDAPLoginForm()
    if form.validate_on_submit():
        flask_login.login_user(form.user)
        return flask.redirect('/')
    return flask.render_template('auth/login.html', form=form)

@blueprint.route('/logout')
@flask_login.login_required
def logout():
    flask_login.logout_user()
    return flask.redirect('/')

