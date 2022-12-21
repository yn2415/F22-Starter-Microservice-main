from flask import Flask, Response, request
from datetime import datetime
import json
from columbia_student_resource import ColumbiaStudentResource
from formula1_resource import Formula1Resource
from flask_cors import CORS
import rest_utils
from middleware import notification

# Create the Flask application object.
app = Flask(__name__)

CORS(app)

trigger_SNS = {'path': '/api/circuits/', 'method': 'PUT'}


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
            "arn:aws:sns:us-east-1:301045768070:MyTopic",
            event
        )

    return response


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

