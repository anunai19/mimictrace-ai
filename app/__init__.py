from flask import Flask, jsonify
from werkzeug.exceptions import RequestEntityTooLarge

from detection.visual_analyzer import MAX_LOGO_IMAGE_BYTES

def create_app():
    app = Flask(__name__)
    app.config["MAX_CONTENT_LENGTH"] = MAX_LOGO_IMAGE_BYTES + 64 * 1024

    @app.errorhandler(RequestEntityTooLarge)
    def handle_request_too_large(_error):
        return jsonify({
            "success": False,
            "error": "Request body exceeds the allowed size.",
        }), 413

    from app.routes import main
    app.register_blueprint(main)

    return app