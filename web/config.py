import json

import flask
import flask_login

from . import db
from . import system

blueprint = flask.Blueprint('config', __name__, url_prefix='/config')

@blueprint.route('/', methods=('GET', 'POST'))
@flask_login.login_required
def index():
    try:
        if not flask_login.current_user.is_admin:
            return flask.Response('forbidden', status=403, mimetype='text/plain')
        with db.locked('settings'):
            if flask.request.method == 'POST':
                form = flask.request.form
                db.write('settings', dict(zip(form.getlist('setting'), form.getlist('value'))))
            settings = db.read('settings')
        return flask.render_template('config/index.html', **locals())
    except Exception as e:
        return flask.Response(f'something went catastrophically wrong: {e}',
                status=400, mimetype='text/plain')

@blueprint.route('/edit/<name>', methods=('GET', 'POST'))
@flask_login.login_required
def edit(name):
    try:
        if not flask_login.current_user.is_admin:
            return flask.Response('forbidden', status=403, mimetype='text/plain')
        if flask.request.method == 'POST':
            form = flask.request.form
            db.save(name, json.loads(form.get('text')))
            system.run(system.save_config)
        content = json.dumps(db.load(name), indent=2)
        return flask.render_template('config/edit.html', **locals())
    except Exception as e:
        return flask.Response(f'something went catastrophically wrong: {e}',
                status=400, mimetype='text/plain')
