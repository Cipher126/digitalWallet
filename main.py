# from flask import Flask
# from error_handling.error_handler import handle_error
#
# app = Flask(__name__)
# handle_error(app)
#
# @app.route('/test')
# def test():
#     from error_handling.errors import InsufficientFundsError
#     raise InsufficientFundsError(details={"available": "500", "required": "1000"})
#
# if __name__ == "__main__":
#     app.run(debug=True)