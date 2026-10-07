# sftp_server

A small password-authenticated SFTP server. Files are served from a configured
root directory, and SFTP paths are prevented from accessing files outside it.

## Requirements

- Python 3.9 or later
- Paramiko 4.0.0 (`python -m pip install -r requirements.txt`)

## Run

Set a username and password, then start the server:

```sh
export SFTP_USERNAME=sftp-user
export SFTP_PASSWORD='choose-a-long-password'
python sftp_server.py --host 127.0.0.1 --port 2222 --root ./sftp-root
```

The server generates an RSA host key at `./sftp_host_key` on first start.
Keep that file private and persistent so clients can recognize the server.
Use `--host 0.0.0.0` to accept connections from other machines, and protect
the connection with network-level controls such as a firewall.

The host, port, root directory, host-key path, username, and password can also
be configured with `SFTP_HOST`, `SFTP_PORT`, `SFTP_ROOT`, `SFTP_HOST_KEY`,
`SFTP_USERNAME`, and `SFTP_PASSWORD`, respectively. Command-line options
override the corresponding environment variables.

## Tests

```sh
python -m unittest discover -s tests
```
