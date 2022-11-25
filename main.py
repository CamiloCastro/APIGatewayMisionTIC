from flask import Flask
from flask import jsonify
from flask import request
from flask_cors import CORS
import json
from waitress import serve
import requests
import datetime
import re

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

@app.before_request
def before_request_callback():
  url = limpiar_url(request.path)
  excluded_routes = ["/login"]
  if url in excluded_routes or request.method.upper() == "OPTIONS":
    print("Ruta excluida del middleware", url)
  else:
    if verify_jwt_in_request():
      usuario = get_jwt_identity()
      rol = usuario["rol"]
      if rol is not None:
        if not validar_permiso(url, request.method.upper(), rol["_id"]):
          print(request.method.upper())
          print(rol["_id"])
          print(url)
          return jsonify({"message": "Permission denied"}), 401
      else:
        return jsonify({"message": "Permission denied"}), 401
    else:
      return jsonify({"message" : "Permission denied"}), 401

def limpiar_url(url):
  partes = url.split("/")

  for p in partes:
    if re.search("\\d", p):
      url = url.replace(p, "?")

  return url


def validar_permiso(url, metodo, id_rol):

  config_data = load_file_config()
  url_seguridad = config_data["url-backend-security"] + "/permisos-roles/validar-permiso/rol/" + id_rol
  headers = {"Content-Type": "application/json; charset=utf-8"}
  body = {
    "url" : url,
    "metodo" : metodo
  }
  response = requests.post(url_seguridad, headers=headers, json=body)
  return response.status_code == 200


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

#Servicios para ESTUDIANTE
@app.route("/estudiante/cedula/<string:cedula>", methods=["GET"])
def estudiante_cedula(cedula):
  config_data = load_file_config()
  url = config_data["url-backend-academic"] + "/estudiante/cedula/" + cedula
  response = requests.get(url)
  return jsonify(response.json())

@app.route("/estudiante", methods=["GET"])
def listar_estudiantes():
  config_data = load_file_config()
  url = config_data["url-backend-academic"] + "/estudiante"
  response = requests.get(url)
  return jsonify(response.json())

@app.route("/estudiante/<string:id>", methods=["DELETE"])
def eliminar_estudiante(id):
  config_data = load_file_config()
  url = config_data["url-backend-academic"] + "/estudiante/" + id
  response = requests.delete(url)
  return jsonify(response.json())

@app.route("/estudiante", methods=["POST"])
def crear_estudiantes():
  config_data = load_file_config()
  url = config_data["url-backend-academic"] + "/estudiante"
  response = requests.post(url, json=request.get_json())
  return jsonify(response.json())

@app.route("/estudiante/<string:id>", methods=["PUT"])
def actualizar_estudiante(id):
  config_data = load_file_config()
  url = config_data["url-backend-academic"] + "/estudiante/" + id
  response = requests.put(url, json=request.get_json())
  return jsonify(response.json())

#Servicios para MATERIAS
@app.route("/materias", methods=["GET"])
def listar_materias():
  config_data = load_file_config()
  url = config_data["url-backend-academic"] + "/materias"
  response = requests.get(url)
  return jsonify(response.json())

@app.route("/materia/<string:id>", methods=["DELETE"])
def eliminar_materia(id):
  config_data = load_file_config()
  url = config_data["url-backend-academic"] + "/materia/" + id
  response = requests.delete(url)
  return jsonify(response.json())

@app.route("/materia", methods=["POST"])
def crear_materia():
  config_data = load_file_config()
  url = config_data["url-backend-academic"] + "/materia"
  response = requests.post(url, json=request.get_json())
  return jsonify(response.json())

@app.route("/materia/<string:id>", methods=["PUT"])
def actualizar_materia(id):
  config_data = load_file_config()
  url = config_data["url-backend-academic"] + "/materia/" + id
  response = requests.put(url, json=request.get_json())
  return jsonify(response.json())

#Servicios para DEPARTAMENTO
@app.route("/departamento", methods=["GET"])
def listar_departamentos():
  config_data = load_file_config()
  url = config_data["url-backend-academic"] + "/departamentos"
  response = requests.get(url)
  return jsonify(response.json())

@app.route("/departamento/<string:id>", methods=["DELETE"])
def eliminar_departamento(id):
  config_data = load_file_config()
  url = config_data["url-backend-academic"] + "/departamento/" + id
  response = requests.delete(url)
  return jsonify(response.json())

@app.route("/departamento", methods=["POST"])
def crear_departamento():
  config_data = load_file_config()
  url = config_data["url-backend-academic"] + "/departamento"
  response = requests.post(url, json=request.get_json())
  return jsonify(response.json())

@app.route("/departamento/<string:id>", methods=["PUT"])
def actualizar_departamento(id):
  config_data = load_file_config()
  url = config_data["url-backend-academic"] + "/departamento/" + id
  response = requests.put(url, json=request.get_json())
  return jsonify(response.json())

#Servicios de USUARIO
@app.route("/usuario/<string:id>", methods=["GET"])
def obtener_usuario(id):
  config_data = load_file_config()
  url = config_data["url-backend-security"] + "/usuarios/" + id
  response = requests.get(url)
  return jsonify(response.json())

#Servicios de INSCRIPCION
@app.route("/inscripcion/estudiante/<string:id>", methods=["GET"])
def listar_inscripciones(id):
  config_data = load_file_config()
  url = config_data["url-backend-academic"] + "/inscripcion/estudiante/" + id
  response = requests.get(url)
  return jsonify(response.json())

@app.route("/inscripcion/<string:id>", methods=["DELETE"])
def eliminar_inscripcion(id):
  config_data = load_file_config()
  url = config_data["url-backend-academic"] + "/inscripcion/" + id
  response = requests.delete(url)
  return jsonify(response.json())

@app.route("/inscripcion", methods=["POST"])
def crear_inscripcion():
  config_data = load_file_config()
  url = config_data["url-backend-academic"] + "/inscripcion"
  response = requests.post(url, json=request.get_json())
  return jsonify(response.json())

@app.route("/inscripcion/<string:id>", methods=["PUT"])
def actualizar_inscripcion(id):
  config_data = load_file_config()
  url = config_data["url-backend-academic"] + "/inscripcion/" + id
  response = requests.put(url, json=request.get_json())
  return jsonify(response.json())

if __name__ == '__main__' :
  data_config = load_file_config()
  print(f"Server running: http://{data_config['url-backend']}:{data_config['port']}")
  serve(app, host=data_config["url-backend"], port=data_config["port"])