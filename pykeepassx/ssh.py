import paramiko
import getpass
from contextlib import contextmanager
import errno


def parse_ssh_filename(filename):
    username = None
    hostname = None
    filepart = None

    if filename.find('@') >= 0:
        username, hostname = filename.split('@')
    else:
        hostname = filename

    if not hostname.find(':') >= 0:
        raise "!"

    hostname, filepart = hostname.split(':')

    return ssh(hostname, username or getpass.getuser()), filepart


class ssh(object):
    def __init__(self, hostname, username):
        self.hostname = hostname
        self.port = 22
        self.username = username
        self.password = None

    def set_password(self, password):
        self.password = password

    def read(self, filename):
        with _ssh(self) as sftp:
            return sftp.open(filename, 'r').read()

    def write(self, filename, data):
        with _ssh(self) as sftp:
            sftp.open(filename, 'w').write(data)

    def exists(self, filename):
        with _ssh(self) as sftp:
            try:
                sftp.stat(filename)
            except IOError as e:
                if e.errno == errno.ENOENT:
                    return False
                raise
            return True

    def rename(self, old, new):
        with _ssh(self) as sftp:
            sftp.rename(old, new)

    def remove(self, filename):
        with _ssh(self) as sftp:
            sftp.remove(filename)


@contextmanager
def _ssh(ssh):
    # FIXME: reuse connection(?)
    try:
        t = paramiko.Transport((ssh.hostname, ssh.port))
        t.connect(username=ssh.username, password=ssh.password)
        sftp = paramiko.SFTPClient.from_transport(t)

        yield sftp
    finally:
        try:
            t.close()
        except:
            pass
