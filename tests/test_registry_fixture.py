from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import importlib.util
from pathlib import Path
import threading
import unittest


ROOT = Path(__file__).resolve().parent.parent
SPEC = importlib.util.spec_from_file_location(
    "container_integration", ROOT / "tests/integration/run_container_integration.py"
)
integration = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(integration)


class RegistryHandler(BaseHTTPRequestHandler):
    location = "/v2/kali-mcp-fixture/blobs/uploads/upload-id?state=kept"
    manifest_digest = None
    manifest_header = True
    requests = []

    def log_message(self, _format, *_args):
        return

    def _reply(self, status, headers=None):
        self.send_response(status)
        for name, value in (headers or {}).items():
            self.send_header(name, value)
        self.end_headers()

    def do_GET(self):
        type(self).requests.append(("GET", self.path, b""))
        self._reply(200)

    def do_HEAD(self):
        type(self).requests.append(("HEAD", self.path, b""))
        self._reply(200, {"Docker-Content-Digest": type(self).manifest_digest or ""})

    def do_POST(self):
        type(self).requests.append(("POST", self.path, b""))
        self._reply(202, {"Location": type(self).location})

    def do_PUT(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        type(self).requests.append(("PUT", self.path, body, self.headers.get("Content-Type")))
        if "/manifests/" in self.path:
            headers = ({"Docker-Content-Digest": type(self).manifest_digest or ""}
                       if type(self).manifest_header else {})
            self._reply(201, headers)
        else:
            digest = self.path.split("digest=", 1)[-1]
            self._reply(201, {"Docker-Content-Digest": digest})


@contextmanager
def registry_server(handler=RegistryHandler):
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


class RegistryPublicationTests(unittest.TestCase):
    def setUp(self):
        RegistryHandler.location = "/v2/kali-mcp-fixture/blobs/uploads/upload-id?state=kept"
        RegistryHandler.requests = []
        RegistryHandler.manifest_digest = None
        RegistryHandler.manifest_header = True

    def test_uploads_deterministic_blobs_and_manifest_with_digest_verification(self):
        payloads = integration.create_oci_payloads("linux/amd64")
        RegistryHandler.manifest_digest = payloads.manifest_digest
        with registry_server() as endpoint:
            actual = integration.publish_oci_fixture(endpoint, payloads, request_timeout=1)
        self.assertEqual(payloads.manifest_digest, actual)
        puts = [request for request in RegistryHandler.requests if request[0] == "PUT"]
        self.assertEqual(3, len(puts))
        self.assertTrue(all("state=kept" in request[1] for request in puts[:2]))
        self.assertTrue(all("digest=sha256%3A" in request[1] for request in puts[:2]))
        self.assertEqual("application/vnd.oci.image.manifest.v1+json", puts[-1][3])

    def test_accepts_same_origin_absolute_location_and_head_digest_fallback(self):
        payloads = integration.create_oci_payloads("linux/amd64")
        RegistryHandler.manifest_digest = payloads.manifest_digest
        RegistryHandler.manifest_header = False
        with registry_server() as endpoint:
            RegistryHandler.location = (
                endpoint + "/v2/kali-mcp-fixture/blobs/uploads/upload-id?state=kept"
            )
            integration.publish_oci_fixture(endpoint, payloads, request_timeout=1)
        self.assertTrue(any(request[0] == "HEAD" for request in RegistryHandler.requests))

    def test_rejects_upload_location_that_changes_registry_origin(self):
        payloads = integration.create_oci_payloads("linux/amd64")
        RegistryHandler.location = "http://127.0.0.1:1/escaped"
        with registry_server() as endpoint, self.assertRaisesRegex(ValueError, "origin"):
            integration.publish_oci_fixture(endpoint, payloads, request_timeout=1)

    def test_rejects_manifest_digest_mismatch(self):
        payloads = integration.create_oci_payloads("linux/amd64")
        RegistryHandler.manifest_digest = "sha256:" + "0" * 64
        with registry_server() as endpoint, self.assertRaisesRegex(ValueError, "manifest digest"):
            integration.publish_oci_fixture(endpoint, payloads, request_timeout=1)

    def test_temporary_fixture_image_is_cleaned_when_publication_fails(self):
        commands = []

        def fake_run(command, **_kwargs):
            commands.append(command)

        with self.assertRaisesRegex(RuntimeError, "upload failed"):
            with integration.temporary_fixture_image("linux/amd64", run_command=fake_run):
                raise RuntimeError("upload failed")
        self.assertEqual("docker", commands[0][0])
        self.assertEqual(["docker", "image", "rm", "-f"], commands[-1][:4])
        self.assertEqual(commands[0][commands[0].index("-t") + 1], commands[-1][-1])


if __name__ == "__main__":
    unittest.main()
