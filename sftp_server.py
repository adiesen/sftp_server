#!/usr/bin/env python3
import argparse
import hmac
import logging
import os
import socketserver
import threading
import time
from pathlib import Path

import paramiko


LOGGER = logging.getLogger("sftp_server")


def _inside_root(root, path):
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


class RootedSFTPServerInterface(paramiko.SFTPServerInterface):
    def __init__(self, server, *args, root, **kwargs):
        super().__init__(server, *args, **kwargs)
        self.root = Path(root).resolve()

    def _resolve(self, path, follow_final=True):
        if not isinstance(path, str) or "\0" in path:
            raise ValueError("Invalid path")
        candidate = self.root / path.lstrip("/")
        if follow_final:
            resolved = candidate.resolve()
        else:
            resolved = candidate.parent.resolve() / candidate.name
        if not _inside_root(self.root, resolved):
            raise PermissionError("Path is outside the SFTP root")
        return resolved

    @staticmethod
    def _error(error):
        return paramiko.SFTPServer.convert_errno(getattr(error, "errno", None) or 1)

    def list_folder(self, path):
        try:
            directory = self._resolve(path)
            entries = []
            for name in os.listdir(directory):
                attributes = paramiko.SFTPAttributes.from_stat(
                    os.stat(directory / name, follow_symlinks=False)
                )
                attributes.filename = name
                entries.append(attributes)
            return entries
        except (OSError, ValueError) as error:
            return self._error(error)

    def stat(self, path):
        try:
            return paramiko.SFTPAttributes.from_stat(os.stat(self._resolve(path)))
        except (OSError, ValueError) as error:
            return self._error(error)

    def lstat(self, path):
        try:
            return paramiko.SFTPAttributes.from_stat(
                os.lstat(self._resolve(path, follow_final=False))
            )
        except (OSError, ValueError) as error:
            return self._error(error)

    def open(self, path, flags, attr):
        try:
            filename = self._resolve(path)
            open_flags = flags | getattr(os, "O_BINARY", 0)

            mode = attr.st_mode & 0o777 if attr.st_mode is not None else 0o666
            descriptor = os.open(filename, open_flags, mode)
            return RootedSFTPHandle(descriptor, flags, filename)
        except (OSError, ValueError) as error:
            return self._error(error)

    def remove(self, path):
        try:
            os.remove(self._resolve(path, follow_final=False))
            return paramiko.SFTP_OK
        except (OSError, ValueError) as error:
            return self._error(error)

    def mkdir(self, path, attr):
        try:
            mode = attr.st_mode & 0o777 if attr.st_mode is not None else 0o777
            os.mkdir(self._resolve(path, follow_final=False), mode)
            return paramiko.SFTP_OK
        except (OSError, ValueError) as error:
            return self._error(error)

    def rmdir(self, path):
        try:
            os.rmdir(self._resolve(path, follow_final=False))
            return paramiko.SFTP_OK
        except (OSError, ValueError) as error:
            return self._error(error)

    def rename(self, oldpath, newpath):
        try:
            source = self._resolve(oldpath, follow_final=False)
            destination = self._resolve(newpath, follow_final=False)
            if os.path.lexists(destination):
                return paramiko.SFTP_FAILURE
            os.rename(source, destination)
            return paramiko.SFTP_OK
        except (OSError, ValueError) as error:
            return self._error(error)

    def posix_rename(self, oldpath, newpath):
        try:
            os.replace(
                self._resolve(oldpath, follow_final=False),
                self._resolve(newpath, follow_final=False),
            )
            return paramiko.SFTP_OK
        except (OSError, ValueError) as error:
            return self._error(error)

    def chattr(self, path, attr):
        try:
            paramiko.SFTPServer.set_file_attr(str(self._resolve(path)), attr)
            return paramiko.SFTP_OK
        except (OSError, ValueError) as error:
            return self._error(error)

    def readlink(self, path):
        try:
            link = os.readlink(self._resolve(path, follow_final=False))
            if os.path.isabs(link):
                link_path = Path(link).resolve()
                if not _inside_root(self.root, link_path):
                    return paramiko.SFTP_PERMISSION_DENIED
                return "/" + link_path.relative_to(self.root).as_posix()
            return link
        except (OSError, ValueError) as error:
            return self._error(error)

    def symlink(self, target_path, path):
        try:
            destination = self._resolve(path, follow_final=False)
            if os.path.isabs(target_path):
                target = (self.root / target_path.lstrip("/")).resolve()
                if not _inside_root(self.root, target):
                    return paramiko.SFTP_PERMISSION_DENIED
                target_path = os.path.relpath(target, destination.parent)
            else:
                target = (destination.parent / target_path).resolve()
                if not _inside_root(self.root, target):
                    return paramiko.SFTP_PERMISSION_DENIED
            os.symlink(target_path, destination)
            return paramiko.SFTP_OK
        except (OSError, ValueError) as error:
            return self._error(error)

    def canonicalize(self, path):
        try:
            relative_path = self._resolve(path).relative_to(self.root)
            return "/" if relative_path == Path(".") else "/" + relative_path.as_posix()
        except (OSError, ValueError):
            return "/"


class RootedSFTPHandle(paramiko.SFTPHandle):
    def __init__(self, descriptor, flags, filename):
        super().__init__(flags)
        self.descriptor = descriptor
        self.filename = filename
        self.open_flags = flags
        self._io_lock = threading.Lock()

    def read(self, offset, length):
        try:
            with self._io_lock:
                os.lseek(self.descriptor, offset, os.SEEK_SET)
                return os.read(self.descriptor, length)
        except OSError as error:
            return self._error(error)

    def write(self, offset, data):
        try:
            with self._io_lock:
                if not self.open_flags & os.O_APPEND:
                    os.lseek(self.descriptor, offset, os.SEEK_SET)
                written = 0
                while written < len(data):
                    count = os.write(self.descriptor, data[written:])
                    if count == 0:
                        return paramiko.SFTP_FAILURE
                    written += count
            return paramiko.SFTP_OK
        except OSError as error:
            return self._error(error)

    def stat(self):
        try:
            return paramiko.SFTPAttributes.from_stat(os.fstat(self.descriptor))
        except OSError as error:
            return self._error(error)

    def chattr(self, attr):
        try:
            paramiko.SFTPServer.set_file_attr(str(self.filename), attr)
            return paramiko.SFTP_OK
        except OSError as error:
            return self._error(error)

    def close(self):
        try:
            os.close(self.descriptor)
        except OSError as error:
            return self._error(error)
        return super().close()

    @staticmethod
    def _error(error):
        return paramiko.SFTPServer.convert_errno(getattr(error, "errno", None) or 1)


class PasswordAuth(paramiko.ServerInterface):
    def __init__(self, username, password):
        self.username = username
        self.password = password

    def check_auth_password(self, username, password):
        if (
            hmac.compare_digest(username.encode(), self.username.encode())
            and hmac.compare_digest(password.encode(), self.password.encode())
        ):
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def get_allowed_auths(self, username):
        return "password"

    def check_channel_request(self, kind, channel_id):
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED


class SFTPRequestHandler(socketserver.BaseRequestHandler):
    def handle(self):
        transport = paramiko.Transport(self.request)
        try:
            transport.add_server_key(self.server.host_key)
            transport.set_subsystem_handler(
                "sftp",
                paramiko.SFTPServer,
                RootedSFTPServerInterface,
                root=self.server.root,
            )
            transport.start_server(
                server=PasswordAuth(self.server.username, self.server.password)
            )
            while transport.is_active():
                time.sleep(0.1)
        except (EOFError, OSError, paramiko.SSHException) as error:
            LOGGER.debug("SSH connection ended: %s", error)
        finally:
            transport.close()


class ThreadedSFTPServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, address, root, username, password, host_key):
        self.root = Path(root).resolve()
        self.username = username
        self.password = password
        self.host_key = host_key
        self.root.mkdir(parents=True, exist_ok=True)
        super().__init__(address, SFTPRequestHandler)


def load_or_create_host_key(path):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        return paramiko.RSAKey.from_private_key_file(str(path))

    key = paramiko.RSAKey.generate(3072)
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        return paramiko.RSAKey.from_private_key_file(str(path))
    try:
        with os.fdopen(descriptor, "w") as key_file:
            key.write_private_key(key_file)
    except Exception:
        path.unlink(missing_ok=True)
        raise
    return key


def main(argv=None):
    parser = argparse.ArgumentParser(description="Run a password-authenticated SFTP server.")
    parser.add_argument("--host", default=os.getenv("SFTP_HOST", "127.0.0.1"))
    parser.add_argument("--port", type=int, default=int(os.getenv("SFTP_PORT", "2222")))
    parser.add_argument(
        "--root", default=os.getenv("SFTP_ROOT", "./sftp-root"), help="SFTP file root"
    )
    parser.add_argument(
        "--host-key", default=os.getenv("SFTP_HOST_KEY", "./sftp_host_key")
    )
    parser.add_argument("--username", default=os.getenv("SFTP_USERNAME"))
    parser.add_argument("--password", default=os.getenv("SFTP_PASSWORD"))
    args = parser.parse_args(argv)
    if not args.username or not args.password:
        parser.error("set SFTP_USERNAME and SFTP_PASSWORD or provide both options")
    if not 0 <= args.port <= 65535:
        parser.error("port must be between 0 and 65535")

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    host_key = load_or_create_host_key(args.host_key)
    with ThreadedSFTPServer(
        (args.host, args.port), args.root, args.username, args.password, host_key
    ) as server:
        LOGGER.info("Serving %s on %s:%s", server.root, args.host, server.server_address[1])
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            LOGGER.info("Shutting down")
            server.shutdown()


if __name__ == "__main__":
    main()
