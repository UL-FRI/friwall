import json

import flask
import flask_login

from . import db
from . import system

blueprint = flask.Blueprint('ipsets', __name__, url_prefix='/ipsets')

@blueprint.route('/', methods=('GET', 'POST'))
@flask_login.login_required
def index():
    if not flask_login.current_user.is_admin:
        return flask.Response('forbidden', status=403, mimetype='text/plain')

    with db.locked():
        ipsets = db.read('ipsets')
        networks = db.read('networks')
        if flask.request.method == 'POST':
            form = flask.request.form
            ipsets = {}
            for name, ip, ip6 in zip(form.getlist('name'), form.getlist('ip'), form.getlist('ip6')):
                if name and name not in networks:
                    ipsets[name] = {
                        'ip': ip.split(),
                        'ip6': ip6.split()
                    }
            db.write('ipsets', ipsets)
            system.run(system.save_config)
            return flask.redirect(flask.url_for('ipsets.index'))
        return flask.render_template('ipsets/index.html', ipsets=ipsets)
