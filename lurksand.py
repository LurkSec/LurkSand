import argparse
import json
import os
import sys
import webbrowser
from http.server import ThreadingHTTPServer, SimpleHTTPRequestHandler
from urllib.parse import parse_qs, urlparse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from sand_engine.malware_sandbox import MalwareSandbox

SAND_ENGINE = MalwareSandbox()

class LurkSandHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        web_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "web_dashboard")
        super().__init__(*args, directory=web_dir, **kwargs)

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        params = parse_qs(parsed.query)

        if path == "/api/sand/summary":
            self.send_json(SAND_ENGINE.get_summary())
        elif path == "/api/sand/analyze":
            name = params.get("name", ["sample.exe"])[0]
            text = params.get("text", [""])[0]
            res = SAND_ENGINE.analyze_binary(name, sample_text=text)
            self.send_json(res)
        else:
            super().do_GET()

    def send_json(self, data):
        body = json.dumps(data, indent=2).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

def main():
    parser = argparse.ArgumentParser(description="LurkSand PE Binary Header & Behavioral Malware Sandbox")
    parser.add_argument("action", nargs="?", default="serve", choices=["serve", "audit"])
    parser.add_argument("--port", type=int, default=8015)
    args = parser.parse_args()

    if args.action == "audit":
        summary = SAND_ENGINE.get_summary()
        print(f"[+] LurkSand Malware Analysis Audit Complete.")
        print(f"[+] Samples Analyzed: {summary['total_analyzed']} (Malicious: {summary['malicious_count']}).")
        for s in summary["recent_analyses"]:
            print(f"  [{s['verdict']}] {s['sample_name']} (Score: {s['threat_score']} | Entropy: {s['entropy']})")
    else:
        server_address = ("", args.port)
        httpd = ThreadingHTTPServer(server_address, LurkSandHandler)
        url = f"http://localhost:{args.port}"
        print(f"[+] LurkSand Engine listening on {url}")
        webbrowser.open(url)
        httpd.serve_forever()

if __name__ == "__main__":
    main()
