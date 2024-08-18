from http.server import SimpleHTTPRequestHandler, HTTPServer
import argparse

class MyHandler(SimpleHTTPRequestHandler):
    def do_GET(self):
        if self.path.endswith('.ps1'):
            self.send_response(200)
            self.send_header('Content-type', 'application/octet-stream')
            self.send_header('Set-Cookie', 'sessionid=abc123; Path=/; HttpOnly')
            self.send_header('Cache-Control', 'no-cache')
            self.send_header('Pragma', 'no-cache')
            self.end_headers()
            ps1_file = self.path.lstrip('/')
            with open(ps1_file, 'rb') as file:
                self.wfile.write(file.read())
        else:
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(b"<html><body><h1>Nothing to see here!</h1></body></html>")

def run_server(port):
    server_address = ('', port)
    httpd = HTTPServer(server_address, MyHandler)
    print(f"Waiting for connection to download the PS file on port {port}...")
    httpd.serve_forever()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Simple HTTP Server for serving PS1 files")
    parser.add_argument("-port", type=int, required=True, help="Port to run the HTTP server on")

    args = parser.parse_args()
    run_server(args.port)
