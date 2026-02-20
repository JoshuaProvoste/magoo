# app_lab.py
from flask import Flask, request, jsonify, make_response
import random

app = Flask(__name__)

forwarded_headers = [
    'Forwarded','X-Forwarded','X-Forwarded-Host','X-Forwarded-By','X-Forwarded-For',
    'X-Forwarded-Server','X-Real-IP','X-Forwarded-Proto','X-Forwarded-For-Original',
    'X-Forward-For','Forwarded-For-IP','X-Originating-IP','X-Forwarded-For-IP',
    'X-Forwarded-Port','X-Remote-IP','X-Remote-Addr','X-Remote-Host','X-Server-Name',
    'X-Client-IP','Client-Ip','X-Host','Origin','Access-Control-Allow-Origin',
    'X-ProxyUser-Ip','X-Cluster-Client-Ip','CF-Connecting-IP','True-Client-IP',
    'X-Backend-Host','X-BlueCoat-Via','X-Forwared-Host','X-From-IP','X-Gateway-Host',
    'X-Ip','X-Original-Host','X-Original-IP','X-Original-Remote-Addr','X-Original-Url',
    'X-Originally-Forwarded-For','X-ProxyMesh-IP','X-True-Client-IP','Proxy-Host',
    'CF-ipcountry','Remote-addr','Remote-host','X-Backend-Server','HTTP-Host',
    'Local-addr','X-CF-URL','Fastly-Client-IP','Home','Host-Name','Host-Liveserver',
    'X-Client-Host','X-Clientip','X-Forwarder-For','X-Machine','X-Network-Info',
    'X-Orig-Client','Xproxy','X-Proxy-Url','Clientip','Hosti','Incap-Client-Ip',
    'X-User','X-Source-IP'
]

# Códigos no-200 para simular "cualquier respuesta distinta de 200"
NON_200_STATUSES = [302, 400, 401, 403, 404, 408, 429, 500, 502, 503, 504]

def canonical_host_from_request() -> str:
    """
    Host efectivo del request (sin puerto). Flask usa Host header / authority.
    """
    # request.host puede ser "example.com:5000"
    return (request.host or "").split(":", 1)[0].strip().lower()

def parse_host_at_value(v: str):
    """
    Si v tiene forma "<left>@<right>", retorna (left, right) ya strippeados.
    Si no, (None, None)
    """
    if not v:
        return None, None
    v = v.strip()
    if "@" not in v:
        return None, None
    left, right = v.split("@", 1)
    left = left.strip().lower()
    right = right.strip()
    if not left or not right:
        return None, None
    return left, right

def find_trigger():
    """
    Dispara SOLO si:
      - existe algún header en forwarded_headers
      - su valor tiene formato "<host_del_request>@<custom>"
      - y <host_del_request> coincide exactamente con el Host real del request
    Retorna (header_usado, valor, custom) o (None, None, None)
    """
    req_host = canonical_host_from_request()
    for h in forwarded_headers:
        v = request.headers.get(h)
        left, right = parse_host_at_value(v)
        if left and right and left == req_host:
            return h, v.strip(), right
    return None, None, None

@app.get("/ok-a")
def ok_a():
    return jsonify(status="ok", route="/ok-a"), 200

@app.get("/ok-b")
def ok_b():
    return jsonify(status="ok", route="/ok-b"), 200

@app.get("/probe")
def probe():
    h, v, custom = find_trigger()
    if not h:
        return jsonify(status="no-trigger", route="/probe", host=canonical_host_from_request()), 200

    status = random.choice(NON_200_STATUSES)

    # Base response body (útil para debugging en el lab)
    body = {
        "status": "triggered",
        "route": "/probe",
        "request_host": canonical_host_from_request(),
        "trigger_header": h,
        "trigger_value": v,
        "picked_status": status,
    }

    resp = make_response(jsonify(body), status)
    resp.headers["X-Triggered-By"] = h
    resp.headers["X-Trigger-Value"] = v
    resp.headers["X-Picked-Status"] = str(status)

    # Si toca 302, simulamos el redirect "a lo inyectado"
    if status == 302:
        # Construimos una URL de demo, como en el reporte
        # (nota: no validamos si custom es dominio o IP; es un lab)
        resp.headers["Location"] = f"http://{custom}/files-pri/demo.png"

    return resp

if __name__ == "__main__":
    # Para lab local-only: host="127.0.0.1"
    # Para docker/vm: host="0.0.0.0"
    app.run(host="0.0.0.0", port=5000, debug=True)