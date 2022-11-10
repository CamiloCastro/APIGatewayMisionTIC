from flask import Flask
from flask import jsonify
from flask import request
from flask_cors import CORS
import json
from waitress import serve
import requests
import datetime

from flask_jwt_extended import create_access_token, verify_jwt_in_request
from flask_jwt_extended import JWTManager
from flask_jwt_extended import get_jwt_identity
from flask_jwt_extended import jwt_required


app = Flask(__name__)
cors = CORS(app)
app.config["JWT_SECRET_KEY"] = "clave-secreta-123"
jwt = JWTManager(app)

def load_file_config():
  with open("config.json") as f:
    return json.load(f)

@app.route("/login", methods=["POST"])
def create_token():
  data = request.get_json()
  config_data = load_file_config()
  url = config_data["url-backend-security"] + "/usuarios/validate"
  headers = {"Content-Type" : "application/json; charset=utf-8"}
  response = requests.post(url, json=data, headers=headers)

  if response.status_code == 200:
    user = response.json()
    expires = datetime.timedelta(seconds=60 * 60 * 24)
    token = create_access_token(identity=user, expires_delta=expires)
    return jsonify({"token" : token, "user_id" : user["_id"]})
  else:
    return jsonify({"msg" : "Usuario o contraseña incorrecta"}), 401


@app.route("/", methods=["GET"])
def test():
  data = {"message": "Servidor del API Gateway corriendo"}
  return jsonify(data)

if __name__ == '__main__' :
  data_config = load_file_config()
  print(f"Server running: http://{data_config['url-backend']}:{data_config['port']}")
  serve(app, host=data_config["url-backend"], port=data_config["port"])