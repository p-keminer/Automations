"""Independent Tor rotation review: local socketpair/temporary lock fixtures only."""
from __future__ import annotations
import contextlib
import fcntl
import hmac
import importlib.util
import io
import os
from pathlib import Path
import socket
import sys
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[4]
spec=importlib.util.spec_from_file_location('tor_rotation_review',ROOT/'pi4/python/auto_tor.py')
tor=importlib.util.module_from_spec(spec)
sys.modules[spec.name]=tor
spec.loader.exec_module(tor)
COOKIE=b'c'*32
NONCE=b'n'*32
SERVER_NONCE=b's'*32


def read_line(sock):
    value=bytearray()
    while not value.endswith(b'\r\n'):
        part=sock.recv(1)
        if not part: return bytes(value)
        value.extend(part)
        if len(value)>4096: raise AssertionError('Unexpected local test request size')
    return bytes(value)


class ControlServer:
    def __init__(self,clock=None,bad_proof=False):
        self.client,self.server=socket.socketpair()
        self.client.settimeout(2);self.server.settimeout(2)
        self.messages,self.errors=[],[]
        self.clock,self.bad_proof=clock,bad_proof
        def work():
            try:
                with self.server as stream:
                    first=read_line(stream);self.messages.append(first)
                    assert first==b'AUTHCHALLENGE SAFECOOKIE '+NONCE.hex().encode()+b'\r\n'
                    proof=hmac.digest(b'Tor safe cookie authentication server-to-controller hash',COOKIE+NONCE+SERVER_NONCE,'sha256')
                    if self.bad_proof: proof=b'x'*32
                    response=b'250 AUTHCHALLENGE SERVERHASH='+proof.hex().encode()+b' SERVERNONCE='+SERVER_NONCE.hex().encode()+b'\r\n'
                    # Genuine stream fragmentation, not a canned recv buffer.
                    for start in range(0,len(response),7):stream.sendall(response[start:start+7])
                    auth=read_line(stream);self.messages.append(auth)
                    if self.bad_proof:
                        assert auth==b''
                        return
                    expected=hmac.digest(b'Tor safe cookie authentication controller-to-server hash',COOKIE+NONCE+SERVER_NONCE,'sha256')
                    assert auth==b'AUTHENTICATE '+expected.hex().encode()+b'\r\n'
                    stream.sendall(b'250 OK\r\n')
                    self.messages.append(read_line(stream));assert self.messages[-1]==b'SETEVENTS SIGNAL\r\n'
                    stream.sendall(b'250 OK\r\n')
                    self.messages.append(read_line(stream));assert self.messages[-1]==b'SIGNAL NEWNYM\r\n'
                    if self.clock is not None:self.clock[0]=108
                    # Unrelated event and action-before-ack are valid interleavings.
                    stream.sendall(b'650 SIGNAL CLEARDNSCACHE\r\n650 SIGNAL NEWNYM\r\n250 OK\r\n')
            except BaseException as exc:self.errors.append(exc)
        self.thread=threading.Thread(target=work,daemon=True)
        self.thread.start()

    def __enter__(self):return self
    def __exit__(self,kind,value,tb):
        self.client.close();self.thread.join(3)
        if self.thread.is_alive():raise AssertionError('Local control peer did not stop')
        if not kind and self.errors:raise AssertionError(self.errors)


class SafeCookieSocketTests(unittest.TestCase):
    def test_fragmented_real_socket_auth_and_action_confirmation(self):
        with ControlServer() as server:
            controller=tor.Control(server.client,COOKIE,nonce=NONCE)
            controller.authenticate();controller.newnym()
        self.assertNotIn(COOKIE.hex().encode(),b''.join(server.messages))
        self.assertEqual(server.messages[-1],b'SIGNAL NEWNYM\r\n')

    def test_bad_real_server_proof_sends_no_authentication_or_signal(self):
        with ControlServer(bad_proof=True) as server:
            with self.assertRaisesRegex(tor.Error,'identity check'):
                tor.Control(server.client,COOKIE,nonce=NONCE).authenticate()
        self.assertEqual(len([x for x in server.messages if x]),1)

    def test_rotation_record_starts_at_confirmed_action_not_request_time(self):
        clock=[100]
        with tempfile.TemporaryDirectory() as folder:
            path=Path(folder)/'rotation.lock'
            # The local lock belongs to this test runner, including under root.
            # Do not require or create the production auto-tor account in a fixture.
            with patch.object(tor,'ROTATION_LOCK',path),patch.object(tor.secrets,'token_bytes',return_value=NONCE), \
                 patch.object(tor.pwd,'getpwnam',return_value=SimpleNamespace(pw_gid=os.getegid())):
                with ControlServer(clock=clock) as server:
                    tor.rotate_client(identity=lambda:(os.geteuid(),COOKIE),connector=lambda:server.client,monotonic=lambda:clock[0])
                self.assertEqual(float(path.read_text()),108)
                clock[0]=117
                with self.assertRaisesRegex(tor.Error,'rate-limited'):
                    tor.rotate_client(identity=lambda:(os.geteuid(),COOKIE),connector=lambda:self.fail('Must not connect'),monotonic=lambda:clock[0])


class RotationLockTests(unittest.TestCase):
    def test_competing_rotation_is_rejected_before_connect(self):
        with tempfile.TemporaryDirectory() as folder:
            path=Path(folder)/'rotation.lock'
            with path.open('w') as held:
                os.chmod(path,0o600)
                fcntl.flock(held,fcntl.LOCK_EX|fcntl.LOCK_NB)
                with patch.object(tor,'ROTATION_LOCK',path), \
                     patch.object(tor.pwd,'getpwnam',return_value=SimpleNamespace(pw_gid=os.getegid())), \
                     self.assertRaisesRegex(tor.Error,'Another Tor rotation'):
                    tor.rotate_client(identity=lambda:(os.geteuid(),COOKIE),connector=lambda:self.fail('Must not connect'))

    def test_symlink_and_hardlink_lock_are_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            target=Path(folder)/'target';target.write_bytes(b'');target.chmod(0o600)
            path=Path(folder)/'rotation.lock'
            path.symlink_to(target)
            with patch.object(tor,'ROTATION_LOCK',path),self.assertRaises((tor.Error,OSError)):
                tor.rotate_client(identity=lambda:(os.geteuid(),COOKIE),connector=lambda:self.fail('Must not connect'))
            path.unlink();os.link(target,path)
            with patch.object(tor,'ROTATION_LOCK',path),self.assertRaises(tor.Error):
                tor.rotate_client(identity=lambda:(os.geteuid(),COOKIE),connector=lambda:self.fail('Must not connect'))
            self.assertEqual(target.read_bytes(),b'')

    def test_nonfinite_future_and_invalid_rotation_records_do_not_connect(self):
        with tempfile.TemporaryDirectory() as folder:
            path=Path(folder)/'rotation.lock'
            for raw in (b'nan',b'inf',b'101',b'-1',b'invalid'):
                path.write_bytes(raw);path.chmod(0o600)
                with self.subTest(raw=raw),patch.object(tor,'ROTATION_LOCK',path),self.assertRaises(tor.Error):
                    tor.rotate_client(identity=lambda:(os.geteuid(),COOKIE),connector=lambda:self.fail('Must not connect'),monotonic=lambda:100)
                self.assertEqual(path.read_bytes(),raw)


def unit_properties(executable=None,extra=''):
    executable=tor.RUNTIME if executable is None else executable
    command='{ path='+executable+' ; argv[]='+tor.RUNTIME+' --rotation-worker 600 ; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; pid=123 ; code=(null) ; status=0/0 }'+extra
    return ('LoadState=loaded\nActiveState=active\nFragmentPath=/run/systemd/transient/'+tor.ROTATION_SERVICE+
            '\nDropInPaths=\nTransient=yes\nUser='+tor.ACCOUNT+'\nGroup='+tor.ACCOUNT+
            '\nExecStart='+command+'\nBindsTo='+tor.RECOVERY_TIMER+'\nType=exec\n')


class TransientUnitReviewTests(unittest.TestCase):
    def test_native_execstart_shape_is_observed(self):
        with patch.object(tor.Platform,'run',return_value=unit_properties()):
            self.assertEqual(tor.Platform().rotation(),{'active':True,'seconds':600})

    def test_exec_path_mismatch_is_not_accepted_from_argv_text(self):
        with patch.object(tor.Platform,'run',return_value=unit_properties('/bin/sh')),self.assertRaises(tor.Error):
            tor.Platform().rotation_stop()

    def test_second_exec_entry_is_not_accepted(self):
        extra=' { path=/bin/true ; argv[]=/bin/true ; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }'
        with patch.object(tor.Platform,'run',return_value=unit_properties(extra=extra)),self.assertRaises(tor.Error):
            tor.Platform().rotation_stop()

    def test_new_worker_has_only_unix_access_and_bound_lifetime(self):
        calls=[]
        def run(args,*a,**kw):
            calls.append(args)
            if args[0]=='systemd-run':return ''
            return 'LoadState=not-found\n' if len(calls)==1 else unit_properties()
        with patch.object(tor.Platform,'run',side_effect=run),patch.object(tor,'trusted_read',return_value=b'fixture'):
            tor.Platform().rotation_start(600)
        command=next(row for row in calls if row[0]=='systemd-run')
        for argument in ('--quiet','--collect','--service-type=exec','--property=User='+tor.ACCOUNT,
                         '--property=Group='+tor.ACCOUNT,'--property=BindsTo='+tor.RECOVERY_TIMER,
                         '--property=After='+tor.RECOVERY_TIMER,'--property=RestrictAddressFamilies=AF_UNIX',
                         '--property=NoNewPrivileges=yes','--property=ProtectSystem=strict'):
            self.assertIn(argument,command)
        self.assertEqual(command[-3:],[tor.RUNTIME,'--rotation-worker','600'])


if __name__=='__main__':unittest.main()
