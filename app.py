import os
from flask import Flask, request, jsonify
import whois
import httplib2
import json

from dotenv import load_dotenv
load_dotenv()
token = os.environ.get("token")

h = httplib2.Http(".cache")


app = Flask(__name__)


@app.route('/', methods=["GET"])
def main():
    routes = ["/domain-lookup/:domain", "/ip-lookup/:ip",
              "lookup?ip=ip or lookup?domain=domain"]
    return "/n".join(routes)


@app.route('/domain-lookup/<domain>', methods=["GET"])
def getDomain(domain):
    w = whois.whois(domain)
    return w


@app.route('/ip-lookup/<ip>', methods=["GET"])
def getIp(ip):
    (resp, content) = h.request(
        f"https://ipinfo.io/{ip}?token={token}", "GET")
    return json.loads(content.decode())


@app.route('/lookup', methods=["GET"])
def lookup():
    if 'domain' in request.args:
        domain = request.args.get("domain")
        w = whois.whois(domain)
        return w
    elif 'ip' in request.args:
        ip = request.args.get("ip")
        (resp, content) = h.request(
            f"https://ipinfo.io/{ip}?token={token}", "GET")
        return json.loads(content.decode())


if __name__ == '__main__':
    app.run()
