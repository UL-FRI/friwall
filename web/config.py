import json

import flask
import flask_login

from . import db
from . import system

blueprint = flask.Blueprint('config', __name__)

@blueprint.route('/', methods=('GET', 'POST'))
@flask_login.login_required
def index():
    if not flask_login.current_user.is_admin:
        return flask.Response('forbidden', status=403, mimetype='text/plain')

    with db.locked():
        settings = db.read('settings')
        if flask.request.method == 'POST':
            form = flask.request.form
            for name, value in form.items():
                if name in settings:
                    settings[name] = value
                db.write('settings', settings)
            system.run(system.save_config)
            return flask.redirect(flask.url_for('config.index'))
        return flask.render_template('config/index.html', settings=settings)

@blueprint.route('/edit/<name>', methods=('GET', 'POST'))
@flask_login.login_required
def edit(name):
    if not flask_login.current_user.is_admin:
        return flask.Response('forbidden', status=403, mimetype='text/plain')
    if flask.request.method == 'POST':
        form = flask.request.form
        db.save(name, json.loads(form.get('text').replace('\r\n', '\n')))
        system.run(system.save_config)
    content = json.dumps(db.load(name), indent=2)
    return flask.render_template('config/edit.html', **locals())
