from flask import Flask, Response, request
from datetime import datetime
import json
from columbia_student_resource import ColumbiaStudentResource
from formula1_resource import Formula1Resource
from flask_cors import CORS
import rest_utils
from middleware import notification
from google_login.db import init_db_command

import os
import sqlite3

from flask import Flask, redirect, request, url_for
from flask_login import (
    LoginManager,
    current_user,
    login_required,
    login_user,
    logout_user,
)
from oauthlib.oauth2 import WebApplicationClient
import requests

from google_login.user import User

os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

# Create the Flask application object.
app = Flask(__name__)

# Configuration
GOOGLE_CLIENT_ID = os.environ.get("GOOGLE_CLIENT_ID", None)
GOOGLE_CLIENT_SECRET = os.environ.get("GOOGLE_CLIENT_SECRET", None)
GOOGLE_DISCOVERY_URL = (
    "https://accounts.google.com/.well-known/openid-configuration"
)

CORS(app)
app.secret_key = os.environ.get("SECRET_KEY") or os.urandom(24)

login_manager = LoginManager()
login_manager.init_app(app)



@login_manager.unauthorized_handler
def unauthorized():
    return "You must be logged in to access this content.", 403

try:
    # init_db_command()
    pass
except sqlite3.OperationalError:
    # Assume it's already been created
    print('aaaaaaa')
    pass

print("Hello")

trigger_SNS = {'path': '/api/circuits/', 'method': 'PUT'}

client = WebApplicationClient(GOOGLE_CLIENT_ID)

@login_manager.user_loader
def load_user(user_id):
    return User.get(user_id)

@app.before_request
def before_request_func():
    print("before_reqest!!!")
    print("request = ", json.dumps(request.path, indent=2, default=str))
    if request.path == '/':

        if current_user.is_authenticated:
            return (
                "<p>Hello, {}! You're logged in! Email: {}</p>"
                "<div><p>Google Profile Picture:</p>"
                '<img src="{}" alt="Google profile pic"></img></div>'
                '<a class="button" href="/logout">Logout</a>'.format(
                    current_user.name, current_user.email, current_user.profile_pic
                )
            )
        else:
            return '<a class="button" href="/login">Google Login</a>'

@app.after_request
def after_request(response):
    print("checking after request")
    print(request.path[:14], request.method, trigger_SNS["method"])
    if request.path[:14] == trigger_SNS["path"] and request.method == trigger_SNS["method"]:

        sns = notification.NotificationMiddlewareHandler.get_sns_client()
        print("Got SNS Client!")
        tps = notification.NotificationMiddlewareHandler.get_sns_topics()
        print("SNS Topics = \n", json.dumps(tps, indent=2))

        event = {
            "URL": request.url,
            "method": request.method
        }
        # if request.json:
        #     event["new_data"] = request.json
        notification.NotificationMiddlewareHandler.send_sns_message(
            "arn:aws:sns:us-east-1:251066837542:MyTopic",
            event
        )

    return response

@app.route("/", methods=["GET"])
def index():
    if current_user.is_authenticated:
        return (
            "<p>Hello, {}! You're logged in! Email: {}</p>"
            "<div><p>Google Profile Picture:</p>"
            '<img src="{}" alt="Google profile pic"></img></div>'
            '<a class="button" href="/logout">Logout</a>'.format(
                current_user.name, current_user.email, current_user.profile_pic
            )
        )
    else:
        return '<a class="button" href="/login">Google Login</a>'

@app.route("/login")
def login():
    # Find out what URL to hit for Google login
    google_provider_cfg = get_google_provider_cfg()
    authorization_endpoint = google_provider_cfg["authorization_endpoint"]

    # Use library to construct the request for login and provide
    # scopes that let you retrieve user's profile from Google

    request_uri = client.prepare_request_uri(
        authorization_endpoint,
        redirect_uri=request.base_url + "/callback",
        scope=["openid", "email", "profile"],
    )
    return redirect(request_uri)


@app.route("/login/callback")
def callback():
    # Get authorization code Google sent back to you
    code = request.args.get("code")

    # Find out what URL to hit to get tokens that allow you to ask for
    # things on behalf of a user
    google_provider_cfg = get_google_provider_cfg()
    token_endpoint = google_provider_cfg["token_endpoint"]

    # Prepare and send request to get tokens! Yay tokens!
    token_url, headers, body = client.prepare_token_request(
        token_endpoint,
        authorization_response=request.url,
        redirect_url=request.base_url,
        code=code,
    )
    token_response = requests.post(
        token_url,
        headers=headers,
        data=body,
        auth=(GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET),
    )

    # Parse the tokens!
    client.parse_request_body_response(json.dumps(token_response.json()))

    # Now that we have tokens (yay) let's find and hit URL
    # from Google that gives you user's profile information,
    # including their Google Profile Image and Email
    userinfo_endpoint = google_provider_cfg["userinfo_endpoint"]
    uri, headers, body = client.add_token(userinfo_endpoint)
    userinfo_response = requests.get(uri, headers=headers, data=body)

    # We want to make sure their email is verified.
    # The user authenticated with Google, authorized our
    # app, and now we've verified their email through Google!
    if userinfo_response.json().get("email_verified"):
        unique_id = userinfo_response.json()["sub"]
        users_email = userinfo_response.json()["email"]
        picture = userinfo_response.json()["picture"]
        users_name = userinfo_response.json()["given_name"]
    else:
        return "User email not available or not verified by Google.", 400

    # Create a user in our db with the information provided
    # by Google
    user = User(
        id_=unique_id, name=users_name, email=users_email, profile_pic=picture
    )

    # Doesn't exist? Add to database
    if not User.get(unique_id):
        User.create(unique_id, users_name, users_email, picture)

    # Begin user session by logging the user in
    login_user(user)

    # Send user back to homepage
    return redirect(url_for("index"))


@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("index"))


def get_google_provider_cfg():
    return requests.get(GOOGLE_DISCOVERY_URL).json()


@app.get("/api/health")
def get_health():
    t = str(datetime.now())
    msg = {
        "name": "F22-Starter-Microservice",
        "health": "Good",
        "at time": t
    }

    # DFF TODO Explain status codes, content type, ... ...
    result = Response(json.dumps(msg), status=200, content_type="application/json")

    return result


@app.route("/api/students/<uni>", methods=["GET"])
def get_student_by_uni(uni):

    result = ColumbiaStudentResource.get_by_key(uni)

    if result:
        rsp = Response(json.dumps(result), status=200, content_type="application.json")
    else:
        rsp = Response("NOT FOUND", status=404, content_type="text/plain")

    return rsp


@app.route("/api/students/address/<uni>", methods=["PUT"])
def update_student_address(uni):
    request_inputs = rest_utils.RESTContext(request)
    svc = ColumbiaStudentResource()
    result = svc.update_by_template(uni, request_inputs.data)

    if result:
        rsp = Response(json.dumps(result), status=200, content_type="application.json")
    else:
        rsp = Response("NOT FOUND", status=404, content_type="text/plain")

    return rsp


@app.route("/api/circuits/<name>", methods=["GET", "PUT", "POST", "DELETE"])
def get_circuit_by_country(name):

    request_inputs = rest_utils.RESTContext(request)
    svc = Formula1Resource()

    if request_inputs.method == "GET":
        result = svc.get_by_key(name)

        if result:
            rsp = Response(json.dumps(result), status=200, content_type="application.json")
        else:
            rsp = Response("NOT FOUND", status=404, content_type="text/plain")
    elif request_inputs.method == "POST":
        result = svc.update_by_key(name, request_inputs.data)
        rsp = Response(json.dumps(result, default=str), status=200, content_type="application/json")
    elif request_inputs.method == "PUT":
        result = svc.create_by_template(request_inputs.data)
        rsp = Response(json.dumps(result, default=str), status=200, content_type="application/json")
    elif request_inputs.method == "DELETE":
        result = svc.delete_by_ref(name)
        rsp = Response(json.dumps(result, default=str), status=200, content_type="application/json")
    else:
        rsp = Response("NOT IMPLEMENTED", status=501, content_type="text/plain")

    return rsp


@app.route("/api/circuits", methods=["GET"])
def get_circuit_by_template():

    request_inputs = rest_utils.RESTContext(request)
    svc = Formula1Resource()
    if request_inputs.method == "GET":
        result = svc.get_by_template(q=request_inputs.args,
                                     limit=request_inputs.limit,
                                     offset=request_inputs.offset)
        # result['links']['prev'] = request.path
        # print(result)
        res = request_inputs.add_pagination(result)
        rsp = Response(json.dumps(res), status=200, content_type="application.json")
    else:
        rsp = Response("NOT FOUND", status=404, content_type="text/plain")
    return rsp

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5011)
    # app.run(ssl_context="adhoc")

