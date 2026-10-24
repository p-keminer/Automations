"""User choices must be explicit and cancellable; redirected input never prompts."""
import importlib.util
import io
from pathlib import Path
import unittest

ROOT=Path(__file__).resolve().parents[4]
spec=importlib.util.spec_from_file_location('selection',ROOT/'common/python/adapter_selection.py')
s=importlib.util.module_from_spec(spec);spec.loader.exec_module(s)


class TTY(io.StringIO):
    def isatty(self):return True


class SelectionTests(unittest.TestCase):
    def test_no_candidate(self):
        with self.assertRaisesRegex(ValueError,'No eligible'):s.choose([], 'ambiguous')

    def test_one_does_not_prompt_even_without_tty(self):
        self.assertEqual(s.choose([('wlan0','one')],'ambiguous',stdin=io.StringIO('2\n')), 'wlan0')

    def test_multiple_noninteractive_does_not_read_input(self):
        source=io.StringIO('1\n');out=io.StringIO()
        with self.assertRaisesRegex(ValueError,'use --interface'):
            s.choose([('wlan0','Alfa'),('wlan1','dongle')],'use --interface',stdin=source,stdout=out)
        self.assertEqual(source.tell(),0);self.assertEqual(out.getvalue(),'')

    def test_number_name_and_retry(self):
        for answer in ('2\n','wlan1\n','99\nwrong\n2\n'):
            out=TTY()
            self.assertEqual(s.choose([('wlan0','Alfa'),('wlan1','dongle')],'ambiguous',stdin=TTY(answer),stdout=out),'wlan1')
            self.assertIn('1. wlan0',out.getvalue());self.assertIn('2. wlan1',out.getvalue())

    def test_eof_and_overlong_are_not_default_choices(self):
        for value in ('','a'*100+'\n'):
            with self.assertRaises(ValueError):s.choose([('wlan0','a'),('wlan1','b')],'ambiguous',stdin=TTY(value),stdout=TTY())

    def test_source_names_multiple_choices_and_numbered_prompt(self):
        options=[('ctrl0','SSID Pi4'),('wlan1','SSID Guests')]
        for answer in ('ctrl0,wlan1\n','2,1,2\n','wrong\n1, 2\n'):
            out=TTY()
            self.assertEqual(s.choose_many(options,'use --from',stdin=TTY(answer),stdout=out),['ctrl0','wlan1'])
            self.assertIn('1. ctrl0',out.getvalue());self.assertIn('2. wlan1',out.getvalue())
            self.assertIn('SSID Guests',out.getvalue())

    def test_explicit_sources_need_no_tty_and_reject_partial_or_unknown_input(self):
        options=[('ctrl0','control'),('wlan1','guest')]
        self.assertEqual(s.choose_many(options,'use --from',answer='wlan1,ctrl0,wlan1'),['ctrl0','wlan1'])
        for answer in ('','ctrl0,','wlan','ctrl0,eth0','1,2','*'):
            with self.assertRaises(ValueError):s.choose_many(options,'use --from',answer=answer)

    def test_sources_always_prompt_even_with_one_candidate(self):
        out=TTY()
        self.assertEqual(s.choose_many([('ctrl0','Pi4')],'use --from',stdin=TTY('ctrl0\n'),stdout=out),['ctrl0'])
        self.assertIn('1. ctrl0',out.getvalue())
        source=io.StringIO('ctrl0\n')
        with self.assertRaisesRegex(ValueError,'--from.*Available: ctrl0'):
            s.choose_many([('ctrl0','Pi4')],'use --from',stdin=source,stdout=io.StringIO())
        self.assertEqual(source.tell(),0)

    def test_source_cancel_empty_retry_and_bound(self):
        for answer in ('','a'*257+'\n'):
            with self.assertRaises(ValueError):s.choose_many([('ctrl0','Pi4')],'x',stdin=TTY(answer),stdout=TTY())
        self.assertEqual(s.choose_many([('ctrl0','Pi4')],'x',stdin=TTY('\n1\n'),stdout=TTY()),['ctrl0'])


if __name__=='__main__':unittest.main()
