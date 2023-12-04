import flask
import flask_login

from . import db
from . import system

blueprint = flask.Blueprint('nat', __name__)

@blueprint.route('/', methods=('GET', 'POST'))
@flask_login.login_required
def index():
    if not flask_login.current_user.is_admin:
        return flask.Response('forbidden', status=403, mimetype='text/plain')

    with db.locked():
        nat = { network: "" for network in db.read('networks') }
        nat |= db.read('nat')
        if flask.request.method == 'POST':
            form = flask.request.form
            for network, address in form.items():
                if network in nat:
                    nat[network] = address
            db.write('nat', nat)
            system.run(system.save_config)
            return flask.redirect(flask.url_for('nat.index'))
        return flask.render_template('nat/index.html', nat=nat)
