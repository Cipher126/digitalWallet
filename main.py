from flask import Flask
from error_handling.error_handler import handle_error
from routes.user_route import user_bp
from routes.admin_route import admin_bp
from routes.wallet_route import wallet_bp
import os
from dotenv import load_dotenv
from firebase_admin import credentials, initialize_app

from routes.webhook import webhook_bp

app = Flask(__name__)
handle_error(app)

app.register_blueprint(user_bp, url_prefix='/api/user')
app.register_blueprint(admin_bp, url_prefix='/api/admin')
app.register_blueprint(wallet_bp, url_prefix='/api/wallet')
app.register_blueprint(webhook_bp)

load_dotenv()

cred = credentials.Certificate(os.getenv("FCM_PATH"))
initialize_app(cred)

if __name__ == "__main__":
    app.run(debug=True)