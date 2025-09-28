from flask import Flask
from error_handling.error_handler import handle_error
from routes.auth_route import auth_bp, limiter

app = Flask(__name__)
handle_error(app)
limiter.init_app(app)

app.register_blueprint(auth_bp)

if __name__ == "__main__":
    app.run(debug=True)