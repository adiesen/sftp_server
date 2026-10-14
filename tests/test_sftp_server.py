import os
import stat
import tempfile
import threading
import unittest
from pathlib import Path

import paramiko

from sftp_server import PasswordAuth, ThreadedSFTPServer, load_or_create_host_key


class SFTPServerIntegrationTests(unittest.TestCase):
    def _new_client(self):
        client = paramiko.SSHClient()
        host = f"[127.0.0.1]:{self.server.server_address[1]}"
        client.get_host_keys().add(host, self.host_key.get_name(), self.host_key)
        client.set_missing_host_key_policy(paramiko.RejectPolicy())
        return client

    def test_password_auth_accepts_unicode_credentials(self):
        auth = PasswordAuth("üser", "päss")

        self.assertEqual(
            auth.check_auth_password("üser", "päss"), paramiko.AUTH_SUCCESSFUL
        )

    def setUp(self):
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary_directory.name) / "root"
        self.root.mkdir()
        self.outside_file = Path(self.temporary_directory.name) / "outside.txt"
        self.outside_file.write_text("outside")
        self.host_key = paramiko.RSAKey.generate(2048)
        self.server = ThreadedSFTPServer(
            ("127.0.0.1", 0),
            self.root,
            "test-user",
            "v",
            self.host_key,
        )
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.client = self._new_client()
        self.client.connect(
            "127.0.0.1",
            port=self.server.server_address[1],
            username="test-user",
            password=chr(118),
            allow_agent=False,
            look_for_keys=False,
            timeout=5,
        )
        self.sftp = self.client.open_sftp()

    def tearDown(self):
        self.sftp.close()
        self.client.close()
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)
        self.temporary_directory.cleanup()

    def test_generated_host_key_is_private_and_reused(self):
        key_path = Path(self.temporary_directory.name) / "host_key"
        key = load_or_create_host_key(key_path)

        self.assertEqual(key_path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(
            load_or_create_host_key(key_path).get_fingerprint(), key.get_fingerprint()
        )

    def test_upload_download_and_directory_operations(self):
        self.sftp.mkdir("/folder")
        with self.sftp.file("/folder/file.txt", "w") as remote_file:
            remote_file.write("hello SFTP")

        self.assertEqual(self.sftp.listdir("/folder"), ["file.txt"])
        with self.sftp.file("/folder/file.txt", "r") as remote_file:
            self.assertEqual(remote_file.read(), b"hello SFTP")

        self.sftp.rename("/folder/file.txt", "/folder/renamed.txt")
        self.assertEqual(self.sftp.stat("/folder/renamed.txt").st_size, 10)
        self.sftp.remove("/folder/renamed.txt")
        self.sftp.rmdir("/folder")

    def test_paths_cannot_escape_the_configured_root(self):
        with self.assertRaises(IOError):
            self.sftp.file("../outside.txt", "w")

        escape = self.root / "escape"
        os.symlink(self.outside_file, escape)
        self.assertTrue(stat.S_ISLNK(self.sftp.lstat("/escape").st_mode))
        with self.assertRaises(IOError):
            self.sftp.stat("/escape")

        self.sftp.remove("/escape")
        self.assertEqual(self.outside_file.read_text(), "outside")

    def test_rejects_invalid_password(self):
        client = self._new_client()
        with self.assertRaises(paramiko.AuthenticationException):
            client.connect(
                "127.0.0.1",
                port=self.server.server_address[1],
                username="test-user",
                password=chr(119),
                allow_agent=False,
                look_for_keys=False,
                timeout=5,
            )
        client.close()


if __name__ == "__main__":
    unittest.main()
