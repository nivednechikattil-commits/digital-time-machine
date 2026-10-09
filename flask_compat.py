"""
Flask Compatibility Module for Digital Time Machine.
Provides a lightweight, zero-dependency WSGI/HTTP web framework implementing Flask's exact API
using Python standard library and Jinja2. Enables full offline functionality.
"""

import os
import sys
import json
import re
import io
import mimetypes
import urllib.parse
from pathlib import Path
from wsgiref.simple_server import make_server
import jinja2

class Request:
    def __init__(self, environ):
        self.environ = environ
        self.method = environ.get("REQUEST_METHOD", "GET").upper()
        self.path = environ.get("PATH_INFO", "/")
        self.query_string = environ.get("QUERY_STRING", "")
        
        # Parse query params
        raw_args = urllib.parse.parse_qs(self.query_string, keep_blank_values=True)
        self.args = {k: v[0] if len(v) == 1 else v for k, v in raw_args.items()}
        
        # Read body
        self.content_length = int(environ.get("CONTENT_LENGTH", 0) or 0)
        self.content_type = environ.get("CONTENT_TYPE", "")
        
        wsgi_input = environ.get("wsgi.input")
        if wsgi_input and self.content_length > 0:
            self.data = wsgi_input.read(self.content_length)
        else:
            self.data = b""

        self.form = {}
        self.files = {}
        self._parsed_json = None
        self._parse_body()

    def _parse_body(self):
        if not self.data:
            return

        if "application/json" in self.content_type:
            try:
                self._parsed_json = json.loads(self.data.decode("utf-8", errors="replace"))
            except Exception:
                self._parsed_json = None

        elif "application/x-www-form-urlencoded" in self.content_type:
            raw_form = urllib.parse.parse_qs(self.data.decode("utf-8", errors="replace"), keep_blank_values=True)
            self.form = {k: v[0] if len(v) == 1 else v for k, v in raw_form.items()}

        elif "multipart/form-data" in self.content_type:
            self._parse_multipart()

    def _parse_multipart(self):
        # Extract boundary
        match = re.search(r'boundary=([^\s;]+)', self.content_type)
        if not match:
            return
        boundary = match.group(1).encode("utf-8")
        if boundary.startswith(b'"') and boundary.endswith(b'"'):
            boundary = boundary[1:-1]
            
        parts = self.data.split(b"--" + boundary)
        for part in parts:
            if not part or part == b"--\r\n" or part == b"--":
                continue
            
            headers_body = part.split(b"\r\n\r\n", 1)
            if len(headers_body) != 2:
                continue
            headers_raw, body_raw = headers_body
            body_clean = body_raw.rstrip(b"\r\n")

            header_str = headers_raw.decode("utf-8", errors="replace")
            # Parse Content-Disposition
            disp_match = re.search(r'Content-Disposition:\s*form-data;\s*name="([^"]+)"(?:;\s*filename="([^"]+)")?', header_str, re.IGNORECASE)
            if disp_match:
                field_name = disp_match.group(1)
                filename = disp_match.group(2)
                
                if filename is not None:
                    # It's a file
                    self.files[field_name] = FileStorage(filename, body_clean)
                else:
                    self.form[field_name] = body_clean.decode("utf-8", errors="replace")

    def get_json(self, silent=True):
        if self._parsed_json is not None:
            return self._parsed_json
        if self.data:
            try:
                return json.loads(self.data.decode("utf-8", errors="replace"))
            except Exception as e:
                if not silent:
                    raise e
        return None

    @property
    def json(self):
        return self.get_json(silent=True)


class FileStorage:
    def __init__(self, filename, data_bytes):
        self.filename = filename
        self._data = data_bytes

    def read(self, size=-1):
        if size == -1:
            return self._data
        return self._data[:size]

    def save(self, destination):
        with open(destination, "wb") as f:
            f.write(self._data)


class Response:
    def __init__(self, response="", status=200, headers=None, mimetype="text/html"):
        self.status = status
        self.mimetype = mimetype
        if isinstance(response, str):
            self.data = response.encode("utf-8")
        elif isinstance(response, bytes):
            self.data = response
        else:
            self.data = str(response).encode("utf-8")

        self.headers = headers or {}
        if "Content-Type" not in self.headers:
            self.headers["Content-Type"] = f"{mimetype}; charset=utf-8"

    @property
    def status_code(self):
        return self.status

    def get_json(self):
        return json.loads(self.data.decode("utf-8"))


# Thread-local / global active request proxy
_active_request = None

class _RequestProxy:
    def __getattr__(self, name):
        global _active_request
        if _active_request is None:
            raise RuntimeError("Working outside of request context.")
        return getattr(_active_request, name)

request = _RequestProxy()

def jsonify(*args, **kwargs):
    if args and kwargs:
        raise TypeError("jsonify() behavior with both args and kwargs is undefined.")
    if len(args) == 1:
        data = args[0]
    elif args:
        data = list(args)
    else:
        data = kwargs
    return Response(json.dumps(data), status=200, mimetype="application/json")

def redirect(location, code=302):
    return Response("", status=code, headers={"Location": location})

class FlaskConfig(dict):
    def from_object(self, obj):
        for key in dir(obj):
            if key.isupper():
                self[key] = getattr(obj, key)

class Flask:
    def __init__(self, import_name, template_folder="templates", static_folder="static", static_url_path="/static"):
        self.import_name = import_name
        self.root_path = Path(sys.modules[import_name].__file__).parent if import_name in sys.modules else Path.cwd()
        self.template_folder = str(self.root_path / template_folder)
        self.static_folder = str(self.root_path / static_folder)
        self.static_url_path = static_url_path
        self.config = FlaskConfig()
        self.routes = []

        # Jinja2 environment setup
        self.jinja_env = jinja2.Environment(
            loader=jinja2.FileSystemLoader(self.template_folder),
            autoescape=jinja2.select_autoescape(["html", "xml"])
        )

    def route(self, rule, methods=None, **options):
        methods = [m.upper() for m in (methods or ["GET"])]
        
        # Convert Flask route syntax <var_name> to regex pattern
        regex_pattern = re.sub(r'<([^>]+)>', r'(?P<\1>[^/]+)', rule)
        regex = re.compile(f"^{regex_pattern}$")

        def decorator(f):
            self.routes.append({
                "rule": rule,
                "regex": regex,
                "methods": methods,
                "endpoint": f.__name__,
                "func": f
            })
            return f
        return decorator

    def render_template(self, template_name, **context):
        template = self.jinja_env.get_template(template_name)
        return Response(template.render(**context), status=200, mimetype="text/html")

    def __call__(self, environ, start_response):
        global _active_request
        req = Request(environ)
        _active_request = req

        path = req.path

        # Handle static files
        if path.startswith(self.static_url_path + "/"):
            rel_path = path[len(self.static_url_path) + 1:]
            static_file = Path(self.static_folder) / rel_path
            if static_file.is_file():
                mime, _ = mimetypes.guess_type(str(static_file))
                mime = mime or "application/octet-stream"
                with open(static_file, "rb") as f:
                    content = f.read()
                resp = Response(content, status=200, mimetype=mime)
                start_response(f"{resp.status} OK", list(resp.headers.items()))
                return [resp.data]
            else:
                resp = Response("Not Found", status=404)
                start_response(f"{resp.status} Not Found", list(resp.headers.items()))
                return [resp.data]

        # Match routes
        for r in self.routes:
            match = r["regex"].match(path)
            if match:
                if req.method not in r["methods"]:
                    resp = jsonify({"error": "Method Not Allowed"}), 405
                    status_line = "405 Method Not Allowed"
                    headers = [("Content-Type", "application/json")]
                    start_response(status_line, headers)
                    return [b'{"error": "Method Not Allowed"}']

                kwargs = match.groupdict()
                try:
                    result = r["func"](**kwargs)
                    if isinstance(result, tuple):
                        res_body, status_code = result[0], result[1]
                        if isinstance(res_body, Response):
                            resp = res_body
                            resp.status = status_code
                        elif isinstance(res_body, (dict, list)):
                            resp = jsonify(res_body)
                            resp.status = status_code
                        else:
                            resp = Response(res_body, status=status_code)
                    elif isinstance(result, Response):
                        resp = result
                    elif isinstance(result, (dict, list)):
                        resp = jsonify(result)
                    else:
                        resp = Response(str(result))

                    status_msg = "OK" if resp.status == 200 else ("Created" if resp.status == 201 else ("Redirect" if resp.status in (301, 302) else "Error"))
                    start_response(f"{resp.status} {status_msg}", list(resp.headers.items()))
                    return [resp.data]
                except Exception as ex:
                    import traceback
                    traceback.print_exc()
                    resp = jsonify({"error": f"Internal Server Error: {str(ex)}"}), 500
                    start_response("500 Internal Server Error", [("Content-Type", "application/json")])
                    return [json.dumps({"error": str(ex)}).encode("utf-8")]

        # Route not matched
        resp = Response("<h1>404 Not Found</h1>", status=404, mimetype="text/html")
        start_response("404 Not Found", list(resp.headers.items()))
        return [resp.data]

    def test_client(self):
        return TestClient(self)

    def run(self, host="127.0.0.1", port=5000, debug=False):
        print(f"[*] Digital Time Machine running on http://{host}:{port}/")
        httpd = make_server(host, port, self)
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\n[*] Server stopped.")


class TestClient:
    def __init__(self, app: Flask):
        self.app = app

    def _request(self, method, path, data=None, json_data=None, query_string=None, headers=None):
        if "?" in path:
            path_part, qs_part = path.split("?", 1)
            path = path_part
            query_string = qs_part if not query_string else f"{qs_part}&{query_string}"

        environ = {
            "REQUEST_METHOD": method.upper(),
            "PATH_INFO": path,
            "QUERY_STRING": query_string or "",
            "wsgi.input": io.BytesIO(),
            "CONTENT_LENGTH": "0",
            "CONTENT_TYPE": "text/plain"
        }
        headers = headers or {}
        
        body = b""
        if json_data is not None:
            body = json.dumps(json_data).encode("utf-8")
            environ["CONTENT_TYPE"] = "application/json"
        elif isinstance(data, dict):
            # Check if any value is FileStorage or tuple (for file upload)
            has_files = any(isinstance(v, (FileStorage, tuple)) for v in data.values())
            if has_files:
                boundary = "----WebKitFormBoundary7MA4YWxkTrZu0gW"
                environ["CONTENT_TYPE"] = f"multipart/form-data; boundary={boundary}"
                buf = io.BytesIO()
                for k, v in data.items():
                    buf.write(f"--{boundary}\r\n".encode("utf-8"))
                    if isinstance(v, tuple):
                        # (filename, data_bytes)
                        fn, content = v[0], v[1]
                        buf.write(f'Content-Disposition: form-data; name="{k}"; filename="{fn}"\r\n'.encode("utf-8"))
                        buf.write(b"Content-Type: application/octet-stream\r\n\r\n")
                        buf.write(content if isinstance(content, bytes) else content.encode("utf-8"))
                        buf.write(b"\r\n")
                    else:
                        buf.write(f'Content-Disposition: form-data; name="{k}"\r\n\r\n'.encode("utf-8"))
                        buf.write(str(v).encode("utf-8"))
                        buf.write(b"\r\n")
                buf.write(f"--{boundary}--\r\n".encode("utf-8"))
                body = buf.getvalue()
            else:
                body = urllib.parse.urlencode(data).encode("utf-8")
                environ["CONTENT_TYPE"] = "application/x-www-form-urlencoded"
        elif isinstance(data, (str, bytes)):
            body = data if isinstance(data, bytes) else data.encode("utf-8")

        environ["CONTENT_LENGTH"] = str(len(body))
        environ["wsgi.input"] = io.BytesIO(body)

        response_status = [200]
        response_headers = []

        def start_response(status, headers_list):
            response_status[0] = int(status.split()[0])
            response_headers.extend(headers_list)

        result = self.app(environ, start_response)
        output_bytes = b"".join(result)
        headers_dict = dict(response_headers)

        return Response(output_bytes, status=response_status[0], headers=headers_dict, mimetype=headers_dict.get("Content-Type", "text/plain"))

    def get(self, path, query_string=None, **kwargs):
        return self._request("GET", path, query_string=query_string, **kwargs)

    def post(self, path, data=None, json=None, **kwargs):
        json_payload = json if json is not None else kwargs.pop("json_data", None)
        return self._request("POST", path, data=data, json_data=json_payload, **kwargs)


def render_template(template_name, **context):
    global _active_request
    # Default app lookup
    return _active_flask_app.render_template(template_name, **context)

_active_flask_app = None
def set_active_flask_app(app):
    global _active_flask_app
    _active_flask_app = app
