import flask
import werkzeug.exceptions

def init_app(app):
    @app.errorhandler(werkzeug.exceptions.HTTPException)
    def http_error(e):
        return e

    @app.errorhandler(TimeoutError)
    def timeout_error(e):
        return flask.render_template('busy.html')

    @app.errorhandler(Exception)
    def internal_server_error(e):
        return flask.Response(f'something went catastrophically wrong: {e}',
                status=500, mimetype='text/plain')

