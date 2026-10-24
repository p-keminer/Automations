"""Lock diagnostics: real private Linux flock plus bounded/race-safe proc fixtures."""
import fcntl
import importlib.util
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[3]
spec=importlib.util.spec_from_file_location('share_lock_diagnostics',ROOT/'python/auto_share.py')
share=importlib.util.module_from_spec(spec);spec.loader.exec_module(share)

class LockOwnerTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name);self.proc=self.root/'proc';self.proc.mkdir()
        self.fd=os.open(self.root/'lock',os.O_RDWR|os.O_CREAT,0o600);self.addCleanup(os.close,self.fd)
        self.info=os.fstat(self.fd);self.pid=43210
        self.process=self.proc/str(self.pid);self.process.mkdir()
        self.stat('123456');self.cgroup('automations-share-watch.service');self.locks()
    def stat(self,start):
        fields=['S']+['0']*18+[start]
        (self.process/'stat').write_text(str(self.pid)+' (command with ) spaces) '+' '.join(fields)+'\n')
    def cgroup(self,service):
        (self.process/'cgroup').write_text('0::/system.slice/'+service+'\n')
    def line(self,pid=None,inode=None,device=None):
        device=device or (os.major(self.info.st_dev),os.minor(self.info.st_dev))
        return '12: FLOCK ADVISORY WRITE %s %x:%x:%s 0 EOF\n'%(pid or self.pid,*device,inode or self.info.st_ino)
    def locks(self,text=None):
        (self.proc/'locks').write_text(self.line() if text is None else text)
    def message(self):return share.sharing_busy_message(self.fd,self.proc)
    def unknown(self):
        value=self.message();self.assertIn('could not be determined',value);self.assertNotIn('Observed owner:',value)
    def test_known_watcher_and_pid(self):
        text=self.message();self.assertIn('Share watcher',text);self.assertIn('automations-share-watch.service',text);self.assertIn('PID 43210',text)
    def test_known_recovery_and_rotation_units(self):
        for unit,label in [('automations-tor-recovery.service','Tor recovery check'),('automations-tor-rotation.service','Tor rotation worker')]:
            with self.subTest(unit=unit):self.cgroup(unit);self.assertIn(label,self.message())
    def test_unknown_unit_only_reports_observed_pid(self):
        self.cgroup('private-user-command.service');text=self.message();self.assertIn('Observed owner: PID 43210',text);self.assertNotIn('private-user-command',text)
    def test_v1_systemd_cgroup(self):
        (self.process/'cgroup').write_text('7:name=systemd:/system.slice/automations-share-watch.service\n');self.assertIn('Share watcher',self.message())
    def test_non_systemd_controller_cannot_label_owner(self):
        (self.process/'cgroup').write_text('7:cpu:/system.slice/automations-share-watch.service\n');self.assertNotIn('Share watcher',self.message())
    def test_wrong_inode_and_device_do_not_identify_owner(self):
        for kwargs in ({'inode':self.info.st_ino+1},{'device':(os.major(self.info.st_dev),os.minor(self.info.st_dev)+1)}):
            with self.subTest(kwargs=kwargs):self.locks(self.line(**kwargs));self.unknown()
    def test_waiting_and_non_flock_records_are_ignored(self):
        self.locks(self.line().replace('FLOCK','POSIX'));self.unknown()
        self.locks(self.line().replace('12: FLOCK','12: -> FLOCK'));self.unknown()
    def test_ambiguous_lock_holders_are_not_guessed(self):
        self.locks(self.line()+self.line(pid=43211));self.unknown()
    def test_missing_process_falls_back_without_breaking_error(self):
        (self.process/'stat').unlink();self.unknown()
    def test_released_or_changed_owner_is_not_reported(self):
        with patch.object(share,'_sharing_lock_pid',side_effect=[self.pid,None]):self.unknown()
    def test_pid_reuse_is_not_reported(self):
        with patch.object(share,'_lock_process_start',side_effect=['123','124']):self.unknown()
    def test_changed_cgroup_is_not_reported(self):
        original=share._lock_proc_text;reads=0
        def read(path,maximum):
            nonlocal reads
            value=original(path,maximum)
            if path.name=='cgroup':
                reads+=1
                if reads==2:value='0::/different.service\n'
            return value
        with patch.object(share,'_lock_proc_text',side_effect=read):self.unknown()
    def test_oversized_or_symlink_proc_file_falls_back(self):
        self.locks('x'*(1024*1024+1));self.unknown()
        (self.proc/'locks').unlink();(self.proc/'locks').symlink_to(self.process/'cgroup');self.unknown()
    def test_malformed_stat_and_lock_table_do_not_raise(self):
        (self.process/'stat').write_text('bad stat');self.unknown()
        self.locks('garbage\n');self.unknown()
    def test_command_line_and_environment_are_not_read(self):
        original=share._lock_proc_text;visited=[]
        def read(path,maximum):visited.append(path.name);return original(path,maximum)
        with patch.object(share,'_lock_proc_text',side_effect=read):self.assertIn('Share watcher',self.message())
        self.assertEqual(set(visited),{'locks','stat','cgroup'})
    def test_real_flock_owner_then_success_after_release(self):
        runtime=self.root/'runtime';runtime.mkdir();(runtime/'run').mkdir(mode=0o700)
        lock=runtime/'run/automations-share.lock'
        code="import fcntl,os,sys; f=os.open(sys.argv[1],os.O_CREAT|os.O_RDWR,0o600); fcntl.flock(f,fcntl.LOCK_EX); print('ready',flush=True); sys.stdin.read(1); os.close(f)"
        process=subprocess.Popen([sys.executable,'-c',code,str(lock)],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
        try:
            self.assertEqual(process.stdout.readline().strip(),'ready')
            platform=share.Platform(runtime,owner=os.getuid())
            with self.assertRaises(share.Busy) as error:
                with platform.lock():self.fail('Contended lock was acquired')
            self.assertIn('Observed owner:',str(error.exception));self.assertIn('PID '+str(process.pid),str(error.exception))
            self.assertIsNone(process.poll())
            process.communicate('x',timeout=5);self.assertEqual(process.returncode,0)
            with platform.lock():pass
        finally:
            if process.poll() is None:process.kill();process.communicate(timeout=5)

if __name__=='__main__':unittest.main()
