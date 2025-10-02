from flask import Flask
from error_handling.error_handler import handle_error
from routes.user_route import user_bp
from routes.admin_route import admin_bp
from routes.wallet_route import wallet_bp

app = Flask(__name__)
handle_error(app)

app.register_blueprint(user_bp, url_prefix='/api/user')
app.register_blueprint(admin_bp, url_prefix='/api/admin')
app.register_blueprint(wallet_bp, url_prefix='/api/wallet')

if __name__ == "__main__":
    app.run(debug=True)