import flask
import flask_login

#from .db import get_db

blueprint = flask.Blueprint('dnat', __name__, url_prefix='/dnat')

@blueprint.route('/', methods=('GET', 'POST'))
@flask_login.login_required
def index():
#    with get_db() as db:
#        if flask.request.method == 'POST':
#            for name, value in flask.request.form.items():
#                db.execute('INSERT INTO setting(name, value) VALUES(:name, :value) ON CONFLICT(name) DO UPDATE SET value = :value', ({"name": name, "value": value}))
#        dnat = [tuple(row) for row in (db.execute('SELECT ext_ip, int_ip FROM dnat'))]
    return flask.render_template('dnat/index.html', **locals())
