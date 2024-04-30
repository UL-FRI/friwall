import json

import flask
import flask_login

from . import db
from . import system

blueprint = flask.Blueprint('ipsets', __name__)

@blueprint.route('/', methods=('GET', 'POST'))
@flask_login.login_required
def index():
    if not flask_login.current_user.is_admin:
        return flask.Response('forbidden', status=403, mimetype='text/plain')

    with db.locked():
        if flask.request.method == 'POST':
            # read network data from NetBox, merge in custom definitions and dump the lot
            ipsets = db.read('networks')
            formdata = zip(*(flask.request.form.getlist(e) for e in ('name', 'ip', 'ip6', 'nat', 'vpn')))
            for name, ip, ip6, nat, vpn in formdata:
                # drop sets with empty names
                if not name:
                    continue
                # assign IPs for custom networks only
                if name not in ipsets:
                    ipsets[name] = { 'ip': ip.split(), 'ip6': ip6.split() }
                # assign NAT and VPN for all networks
                ipsets[name] |= { 'nat': nat, 'vpn': vpn }
            db.write('ipsets', ipsets)
            system.run(system.save_config)
            return flask.redirect(flask.url_for('ipsets.index'))

        # read network data from NetBox and merge in custom definitions
        ipsets = db.read('networks')
        for name, data in db.read('ipsets').items():
            # keep static IPs if there are any, otherwise set custom flag for this set
            ipsets[name] = data | ipsets.get(name, {'custom': True})

        return flask.render_template('ipsets/index.html', ipsets=ipsets)
