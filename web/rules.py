import flask
import flask_login

from . import db
from . import system

blueprint = flask.Blueprint('rules', __name__)

@blueprint.route('/', methods=('GET', 'POST'))
@flask_login.login_required
def index():
    if not flask_login.current_user.is_admin:
        return flask.Response('forbidden', status=403, mimetype='text/plain')

    if flask.request.method == 'POST':
        with db.locked():
            rules = db.read('rules')
            form = flask.request.form
            oldrules = {rule['name']: rule for rule in rules}
            rules = []
            for index, name in sorted(
                    zip(form.getlist('index'), form.getlist('name')), key=lambda e: int(e[0] or 0)):
                if index and name:
                    rules.append(oldrules.get(name, {'name': name}))
            db.write('rules', rules)
        system.run(system.save_config)

    return flask.render_template('rules/index.html', rules=db.load('rules'))

@blueprint.route('/edit/<int:index>', methods=('GET', 'POST'))
@flask_login.login_required
def edit(index):
    try:
        if not flask_login.current_user.is_admin:
            return flask.Response('forbidden', status=403, mimetype='text/plain')

        if flask.request.method == 'POST':
            with db.locked():
                form = flask.request.form
                rules = db.read('rules')
                rules[index]['name'] = form.get('name')
                rules[index]['text'] = form.get('text').replace('\r\n', '\n')
                rules[index]['managers'] = [m for m in form.getlist('manager') if m]
                db.write('rules', rules)
            system.run(system.save_config)

        with db.locked():
            ipsets = db.read('ipsets')
        return flask.render_template('rules/edit.html', index=index, rule=db.load('rules')[index], ipsets=ipsets)
    except IndexError as e:
        return flask.Response(f'invalid rule: {index}', status=400, mimetype='text/plain')

def can_toggle(user, rule):
    return user.is_admin or not user.groups.isdisjoint(rule.get('managers', ()))

@blueprint.route('/manage', methods=('GET', 'POST'))
@flask_login.login_required
def manage():
    with db.locked():
        rules = db.read('rules')
        allowed = set(rule['name'] for rule in rules if can_toggle(flask_login.current_user, rule))
        if flask.request.method == 'POST':
            # check that all posted rules are allowed for this user
            posted = set(flask.request.form.getlist('rule'))
            if posted - allowed:
                return flask.Response('forbidden', status=403, mimetype='text/plain')

            # set status for posted rules
            enabled = set(flask.request.form.getlist('enabled'))
            for rule in rules:
                if rule['name'] in posted:
                    rule['enabled'] = (rule['name'] in enabled)
            db.write('rules', rules)
            system.run(system.save_config)
            return flask.redirect(flask.url_for('rules.manage'))
    return flask.render_template('rules/manage.html', rules=[rule for rule in rules if rule['name'] in allowed])
