"""Template selection, immutable static snapshots and real HTTP delivery."""
from functools import partial
import importlib.util
import http.client
import io
import os
from pathlib import Path
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from unittest.mock import Mock

ROOT = Path(__file__).resolve().parents[4]
spec = importlib.util.spec_from_file_location('portal_test', ROOT/'common/python/portal_templates.py')
portal = importlib.util.module_from_spec(spec)
spec.loader.exec_module(portal)


class PortalTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.templates = self.root/'templates'
        self.templates.mkdir()
        self.options = dict(owner_uid=os.getuid(), anchor=self.root)
        self.add('welcome')

    def add(self, name, page='<h1>{{SSID}}</h1>'):
        directory = self.templates/name
        directory.mkdir()
        (directory/'index.html').write_text(page)
        return directory

    def snapshot(self, name='welcome'):
        return portal.snapshot(name, self.templates, **self.options)

    def test_selects_explicit_directory_name(self):
        self.add('second')
        self.assertEqual(portal.select('second', self.templates, **self.options), 'second')

    def test_omitted_template_asks_even_for_a_single_option(self):
        tty = Mock(); tty.isatty.return_value = True
        output = io.StringIO(); output.isatty = lambda: True
        reader = Mock(return_value='1')
        result = portal.select(None, self.templates, reader=reader, stdin=tty, stdout=output, **self.options)
        self.assertEqual(result, 'welcome')
        reader.assert_called_once()
        self.assertIn('1. welcome', output.getvalue())

    def test_interactive_choice_accepts_directory_name_and_lists_sorted_options(self):
        self.add('alpha')
        tty = Mock(); tty.isatty.return_value = True
        output = io.StringIO(); output.isatty = lambda: True
        result = portal.select(None, self.templates, reader=lambda _: 'welcome', stdin=tty, stdout=output, **self.options)
        self.assertEqual(result, 'welcome')
        self.assertLess(output.getvalue().index('1. alpha'), output.getvalue().index('2. welcome'))

    def test_noninteractive_missing_selection_lists_options_without_starting(self):
        stream = io.StringIO()
        with self.assertRaisesRegex(portal.Error, '--template NAME.*welcome'):
            portal.select(None, self.templates, stdin=stream, stdout=stream, **self.options)

    def test_paths_urls_unknown_names_and_zero_choice_are_rejected(self):
        for value in ('../welcome', '/tmp/welcome', 'https://example.test/', 'missing', '0', 'welcome\n'):
            with self.subTest(value=value), self.assertRaises(portal.Error):
                portal.select(value, self.templates, **self.options)

    def test_cancel_does_not_fall_back_to_a_default(self):
        tty = Mock(); tty.isatty.return_value = True
        with self.assertRaisesRegex(portal.Error, 'cancelled'):
            portal.select(None, self.templates, reader=Mock(side_effect=EOFError), stdin=tty, stdout=tty, **self.options)

    def test_incomplete_or_linked_directories_are_not_offered(self):
        (self.templates/'empty').mkdir()
        (self.templates/'linked').symlink_to(self.templates/'welcome')
        self.assertEqual(portal.names(self.templates, **self.options), ['welcome'])

    def test_nested_assets_are_copied_and_only_html_ssid_is_escaped(self):
        directory = self.templates/'welcome'
        (directory/'assets').mkdir()
        (directory/'assets/style.css').write_bytes(b'body { color: red; }')
        (directory/'assets/app.js').write_bytes(b'/* static JS */')
        (directory/'assets/picture.png').write_bytes(b'\x89PNG\r\n\x1a\n')
        files = portal.render(self.snapshot(), '<guest & "name">')
        self.assertEqual(files['index.html'], b'<h1>&lt;guest &amp; &quot;name&quot;&gt;</h1>')
        runtime = self.root/'web'
        portal.write_runtime(runtime, files, **self.options)
        portal.verify_runtime(runtime, portal.manifest(files), **self.options)
        self.assertEqual((runtime/'assets/style.css').read_bytes(), files['assets/style.css'])
        portal.remove_runtime(runtime, portal.manifest(files), **self.options)
        self.assertFalse(runtime.exists())
        self.assertTrue((directory/'index.html').exists())

    def test_plain_html_without_placeholder_is_supported(self):
        self.add('plain', '<!doctype html><title>Local information</title>')
        self.assertEqual(portal.render(self.snapshot('plain'), 'Guest'), self.snapshot('plain'))

    def test_source_edit_does_not_change_the_active_snapshot(self):
        source = self.snapshot()
        before = portal.digest(source)
        (self.templates/'welcome/index.html').write_text('<h1>New version</h1>')
        self.assertEqual(portal.digest(source), before)
        self.assertNotEqual(portal.digest(self.snapshot()), before)

    def test_symlink_hardlink_and_special_assets_are_refused(self):
        path = self.templates/'welcome/asset'
        for kind in ('symlink', 'hardlink', 'fifo'):
            with self.subTest(kind=kind):
                if kind == 'symlink': path.symlink_to(self.templates/'welcome/index.html')
                elif kind == 'hardlink': os.link(self.templates/'welcome/index.html', path)
                else: os.mkfifo(path)
                try:
                    with self.assertRaises(portal.Error): self.snapshot()
                finally:
                    path.unlink()

    def test_user_writable_assets_and_template_roots_are_refused(self):
        for path in (self.templates, self.templates/'welcome', self.templates/'welcome/index.html'):
            before = path.stat().st_mode & 0o777
            path.chmod(0o777)
            try:
                with self.assertRaises(portal.Error): self.snapshot()
            finally:
                path.chmod(before)

    def test_size_and_file_count_limits_fail_before_runtime_creation(self):
        path = self.templates/'welcome/large.bin'
        with path.open('wb') as stream:
            stream.truncate(portal.MAX_FILE+1)
        with self.assertRaisesRegex(portal.Error, '2 MiB'): self.snapshot()
        path.unlink()
        for number in range(portal.MAX_FILES):
            (self.templates/f'welcome/file-{number}').write_text('x')
        with self.assertRaisesRegex(portal.Error, '64 files'): self.snapshot()

    def test_non_utf8_and_nul_html_are_refused(self):
        for data in (b'\xff', b'<html>\0</html>'):
            (self.templates/'welcome/index.html').write_bytes(data)
            with self.assertRaises((portal.Error, UnicodeError)): self.snapshot()

    def test_changed_or_unknown_runtime_files_are_preserved_on_cleanup(self):
        for change in ('modified', 'foreign', 'linked'):
            files = self.snapshot()
            runtime = self.root/change
            portal.write_runtime(runtime, files, **self.options)
            if change == 'modified': (runtime/'index.html').write_text('root edit')
            elif change == 'foreign': (runtime/'foreign.txt').write_text('keep')
            else: (runtime/'foreign').symlink_to(self.root)
            with self.subTest(change=change), self.assertRaises(portal.Error):
                portal.remove_runtime(runtime, portal.manifest(files), **self.options)
            self.assertTrue(runtime.exists())

    def test_invalid_saved_manifest_cannot_escape_runtime(self):
        for manifest in ({'../outside':'a'*64}, {'index.html':'invalid'}, {}, {'index.html':'a'*64, '/tmp/x':'b'*64}):
            with self.subTest(manifest=manifest), self.assertRaises(portal.Error):
                portal.validate_manifest(manifest)

    def test_real_http_serves_assets_probe_routes_and_rejects_traversal_and_post(self):
        files = self.snapshot()
        files.update({'assets/style.css': b'body{color:red}', 'assets/app.js': b'console.log("local")'})
        runtime = self.root/'web'
        portal.write_runtime(runtime, files, **self.options)
        server = portal.ThreadingHTTPServer(('127.0.0.1', 0), partial(portal.Handler, directory=str(runtime)))
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            base = 'http://127.0.0.1:' + str(server.server_port)
            for path, expected in (('/', files['index.html']), ('/assets/style.css', files['assets/style.css']),
                                   ('/assets/app.js', files['assets/app.js'])):
                with urllib.request.urlopen(base+path) as response:
                    self.assertEqual(response.read(), expected)
                    self.assertIn("script-src 'self'", response.headers['Content-Security-Policy'])
            with urllib.request.urlopen(base+'/assets/style.css') as response:
                self.assertIn('text/css', response.headers['Content-Type'])
            for path in sorted(portal.CAPTIVE_PATHS):
                connection=http.client.HTTPConnection('127.0.0.1',server.server_port,timeout=5)
                connection.request('GET',path)
                response=connection.getresponse()
                self.assertEqual(response.status,302,path)
                self.assertEqual(response.getheader('Location'),'http://10.79.0.1/')
                self.assertEqual(response.read(),b'')
                connection.close()
            for host in ('captive.apple.com','www.msftconnecttest.com','detectportal.firefox.com','untrusted.invalid'):
                connection=http.client.HTTPConnection('127.0.0.1',server.server_port,timeout=5)
                connection.request('GET','/',headers={'Host':host})
                response=connection.getresponse()
                self.assertEqual(response.status,302,host)
                self.assertEqual(response.getheader('Location'),'http://10.79.0.1/')
                self.assertNotIn(host,response.getheader('Location'))
                response.read();connection.close()
            for path in ('/%2e%2e/index.html', '/.secret', '/assets/missing.css', '/assets/'):
                with self.subTest(path=path), self.assertRaises(urllib.error.HTTPError):
                    urllib.request.urlopen(base+path)
            with self.assertRaises(urllib.error.HTTPError) as error:
                urllib.request.urlopen(urllib.request.Request(base+'/', data=b'field=value'))
            self.assertEqual(error.exception.code, 501)
        finally:
            server.shutdown(); server.server_close(); thread.join(5)


if __name__ == '__main__':
    unittest.main()
