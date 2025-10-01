from flask import Flask
from error_handling.error_handler import handle_error
from routes.user_route import user_bp

app = Flask(__name__)
handle_error(app)

app.register_blueprint(user_bp, url_prefix='/api/user')

if __name__ == "__main__":
    app.run(debug=True)