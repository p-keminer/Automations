import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[4]
SPEC = importlib.util.spec_from_file_location('auto_cli', ROOT / 'common/python/auto.py')
cli = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(cli)


class AutoCliTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.commands = self.root / 'commands'
        self.commands.mkdir()

    def payload(self, name='cert', content='#!/bin/sh\nexit 0\n', mode=0o755):
        path = self.commands / name
        path.write_text(content)
        path.chmod(mode)
        return path

    def invoke(self, args, execute=None):
        out, err = io.StringIO(), io.StringIO()
        kwargs = {} if execute is None else {'execute': execute}
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = cli.main(args, directory=self.commands, _profile_root=self.root, **kwargs)
        return code, out.getvalue(), err.getvalue()

    def test_help_discovers_without_executing_and_hides_noncommands(self):
        marker = self.root / 'must-not-exist'
        self.payload('cert', f'#!/bin/sh\ntouch {marker}\n')
        self.payload('not-executable', mode=0o644)
        self.payload('bad.name')
        (self.commands / 'linked').symlink_to(self.commands / 'cert')
        (self.commands / 'folder').mkdir()
        code, out, err = self.invoke(['--help'])
        self.assertEqual(code, 0)
        self.assertIn('  cert\n', out)
        self.assertNotIn('linked', out)
        self.assertNotIn('folder', out)
        self.assertNotIn('not-executable', out)
        self.assertFalse(marker.exists())
        self.assertEqual(err, '')

    def test_missing_components_have_honest_help(self):
        code, out, _ = self.invoke([])
        self.assertEqual(code, 0)
        self.assertIn('No optional commands are installed.', out)

    def test_unknown_and_path_arguments_never_execute(self):
        calls = []
        for name in ('ssh', '../cert', '/bin/sh', 'cert;echo', '--status'):
            with self.subTest(name=name):
                code, _, err = self.invoke([name], lambda *args: calls.append(args))
                self.assertEqual(code, 64)
                self.assertIn('ERROR:', err)
        self.assertEqual(calls, [])

    def test_arguments_remain_literal(self):
        path = self.payload()
        calls = []
        with patch.object(cli.os, 'geteuid', return_value=1000):
            code, _, _ = self.invoke(['cert', '--help', 'a b', '$(touch nope)'],
                                    lambda *args: calls.append(args))
        self.assertEqual(code, 0)
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0][:2], (str(path), [str(path), '--help', 'a b', '$(touch nope)']))

    def test_dispatch_uses_system_path_and_english_locale(self):
        self.payload()
        calls = []
        with patch.object(cli.os, 'geteuid', return_value=1000), \
                patch.dict(os.environ, {'PATH': '/tmp/untrusted', 'LC_ALL': 'de_DE.UTF-8'}):
            code, _, _ = self.invoke(['cert', '--help'], lambda *args: calls.append(args))
            self.assertEqual(os.environ['PATH'], '/tmp/untrusted')
        self.assertEqual(code, 0)
        self.assertEqual(calls[0][2]['PATH'], '/usr/sbin:/usr/bin:/sbin:/bin')
        self.assertEqual(calls[0][2]['LC_ALL'], 'C')

    def test_privileged_writable_payload_is_rejected(self):
        self.payload(mode=0o777)
        calls = []
        with patch.object(cli.os, 'geteuid', return_value=0):
            code, _, err = self.invoke(['cert', '--off'], lambda *args: calls.append(args))
        self.assertEqual(code, 1)
        self.assertIn('root-owned', err)
        self.assertEqual(calls, [])

    def test_real_dispatch_preserves_child_exit_status(self):
        path = self.payload(content='#!/bin/sh\nexit 7\n')
        code = ('import importlib.util,sys; '
                's=importlib.util.spec_from_file_location("a",sys.argv[1]); '
                'm=importlib.util.module_from_spec(s); s.loader.exec_module(m); '
                'm.validate_privileged_command=lambda p:None; '
                'sys.exit(m.main(["cert"],directory=m.Path(sys.argv[2]),_profile_root=m.Path(sys.argv[2]).parent))')
        result = subprocess.run(['/usr/bin/python3', '-c', code,
                                 str(ROOT / 'common/python/auto.py'), str(path.parent)],
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 7)

    def test_completion_does_not_execute_payload_or_completion_data(self):
        self.payload()
        marker = self.root / 'must-not-exist'
        data = self.root / 'data'
        data.mkdir()
        (data / 'cert').write_text(f'--on\n--off\n--status\n$(touch {marker})\n')
        source = (ROOT / 'common/shell/bash/auto-completion.sh').read_text()
        # Only fixture paths change; installed completion uses a fixed reader.
        reader_source = (ROOT / 'common/python/auto_completion.py').read_text()
        reader_source = reader_source.replace("_profile_root=Path('/')",
                                              "_profile_root=Path(" + repr(str(self.root)) + ")")
        reader_source = reader_source.replace('/usr/local/libexec/automations', str(self.commands))
        reader_source = reader_source.replace('/usr/local/share/automations/completions', str(data))
        reader = self.root / 'completion.py'
        reader.write_text(reader_source)
        source = source.replace('/usr/local/libexec/automations-support/completion.py', str(reader))
        script = source + '\nCOMP_WORDS=(auto cert --o); COMP_CWORD=2; _auto_complete; printf "%s\\n" "${COMPREPLY[@]}"\n'
        result = subprocess.run(['bash', '--noprofile', '--norc'], input=script,
                                text=True, capture_output=True, check=True)
        self.assertEqual(result.stdout.splitlines(), ['--on', '--off'])
        self.assertFalse(marker.exists())

    def test_launcher_preserves_literal_arguments_and_exit_status(self):
        source = (ROOT / 'common/components/auto-cli/files/auto-launcher.sh').read_text()
        self.assertEqual(source, '#!/bin/sh\nexec /usr/local/bin/auto "$@"\n')
        stub = self.root / 'dispatcher'
        stub.write_text('#!/usr/bin/python3\nimport json,sys\n'
                        'print(json.dumps(sys.argv[1:]))\nsys.exit(7)\n')
        stub.chmod(0o755)
        # Substitute only the absolute destination in the test fixture; the
        # shipped launcher always names /usr/local/bin/auto literally.
        launcher = self.root / 'launcher'
        launcher.write_text(source.replace('/usr/local/bin/auto', str(stub)))
        args = ['wifi', 'two words', '', '$(touch nope)', '*', '--interface', 'wlan1']
        result = subprocess.run(['/bin/sh', str(launcher), *args],
                                capture_output=True, text=True,
                                env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin'})
        self.assertEqual(json.loads(result.stdout), args)
        self.assertEqual(result.returncode, 7)


if __name__ == '__main__':
    unittest.main()
