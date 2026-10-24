import importlib.util
import io
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[4]

def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

support = load("fan_support_fixture", ROOT / "pi4/python/fan_off.py")
cli = load("fan_cli_fixture", ROOT / "pi4/python/auto_fan.py")


class GPIO:
    line = SimpleNamespace(Direction=SimpleNamespace(OUTPUT="output"), Value=SimpleNamespace(ACTIVE=1, INACTIVE=0))
    def __init__(self):
        self.used, self.consumer, self.high = True, "gpio-fan@0", 0
        self.error, self.requests, self.releases = None, [], 0
    def Chip(self, path):
        gpio = self
        class Chip:
            def __enter__(self): return self
            def __exit__(self, *_): pass
            def get_info(self): return SimpleNamespace(label="pinctrl-bcm2711", num_lines=58, name="gpiochip0")
            def get_line_info(self, offset):
                assert offset == 14
                return SimpleNamespace(used=gpio.used, consumer=gpio.consumer)
        return Chip()
    def LineSettings(self, **options): return options
    def request_lines(self, path, **options):
        self.requests.append((path, options))
        if self.error: raise self.error
        self.used, self.consumer, self.high = True, options["consumer"], 0
        gpio = self
        class Request:
            def get_value(self, offset):
                assert offset == 14
                return gpio.high
            def release(self):
                gpio.used, gpio.consumer = False, None
                gpio.releases += 1
        return Request()


class HardwareTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.gpio = GPIO()
        self.hw = support.Hardware(self.root, self.gpio)
        self.events = []
        self.write("proc/device-tree/model", b"Raspberry Pi 4 Model B Rev 1.5\0")
        self.node = self.root / "sys/bus/platform/devices/gpio-fan@0/of_node"
        self.write_node("compatible", b"gpio-fan\0")
        self.write_node("gpios", struct.pack(">3I", 1, 14, 0))
        self.write_node("gpio-fan,speed-map", struct.pack(">4I", 0, 0, 5000, 1))
        self.write_node("phandle", struct.pack(">I", 12))
        self.zone = "sys/firmware/devicetree/base/thermal-zones/cpu-thermal/"
        self.write(self.zone + "cooling-maps/arbitrary-map/cooling-device", struct.pack(">3I", 12, 1, 1))
        self.write(self.zone + "cooling-maps/arbitrary-map/trip", struct.pack(">I", 24))
        self.write(self.zone + "trips/custom-trip/phandle", struct.pack(">I", 24))
        self.write(self.zone + "trips/custom-trip/type", b"active\0")
        self.write(self.zone + "trips/custom-trip/temperature", struct.pack(">I", 60000))
        self.write(self.zone + "trips/custom-trip/hysteresis", struct.pack(">I", 10000))
        self.thermal = "sys/class/thermal/thermal_zone9/"
        for name, value in {"type": "cpu-thermal", "mode": "enabled", "temp": "56000", "trip_point_2_type": "critical"}.items():
            self.write(self.thermal + name, value.encode())
        self.write("sys/bus/gpio/devices/gpiochip0/of_node/phandle", struct.pack(">I", 1))
        self.write("dev/gpiochip0", b"")
        self.hw.driver.mkdir(parents=True)
        (self.hw.device / "driver").symlink_to(self.hw.driver)
        self.write("sys/bus/platform/devices/gpio-fan@0/hwmon/hwmon7/name", b"gpio_fan")
        self.write("sys/bus/platform/devices/gpio-fan@0/hwmon/hwmon7/pwm1", b"0")
        def driver_write(action):
            self.events.append(action)
            if action == "unbind":
                (self.hw.device / "driver").unlink()
                self.gpio.used, self.gpio.consumer = False, None
            else:
                (self.hw.device / "driver").symlink_to(self.hw.driver)
                self.gpio.used, self.gpio.consumer = True, self.hw.device.name
        self.hw.driver_write = driver_write
    def write(self, relative, data):
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    def write_node(self, name, data):
        self.node.mkdir(parents=True, exist_ok=True)
        (self.node / name).write_bytes(data)
    def test_resolves_trip_by_phandle_and_real_thermal_type(self):
        self.assertEqual(self.hw.inspect(), {"on_celsius":60, "off_celsius":50, "temperature_millidegrees":56000, "bound":True})
        self.assertFalse(self.hw.kernel_output())
    def test_missing_overlay_has_reboot_diagnostic(self):
        self.node.rename(self.node.with_name("missing"))
        with self.assertRaisesRegex(support.FanError, "configured fan image and reboot"):
            self.hw.inspect()
    def test_wrong_model_pin_polarity_and_speed_map_are_rejected(self):
        for file, data in [("gpios", struct.pack(">3I",1,15,0)), ("gpios", struct.pack(">3I",1,14,1)),
                           ("gpio-fan,speed-map", struct.pack(">4I",0,0,5000,0))]:
            original = (self.node / file).read_bytes()
            with self.subTest(file=file, data=data):
                self.write_node(file,data)
                with self.assertRaises(support.FanError): self.hw.inspect()
                self.write_node(file,original)
        self.write("proc/device-tree/model", b"Raspberry Pi 5")
        with self.assertRaisesRegex(support.FanError, "Pi 4"): self.hw.inspect()
    def test_ambiguous_cooling_map_is_rejected(self):
        self.write(self.zone + "cooling-maps/second/cooling-device", struct.pack(">3I",12,1,1))
        with self.assertRaisesRegex(support.FanError, "one supported CPU cooling map"): self.hw.inspect()
    def test_wrong_trip_and_noninteger_threshold_are_rejected(self):
        self.write(self.zone + "trips/custom-trip/type", b"critical\0")
        with self.assertRaises(support.FanError): self.hw.inspect()
        self.write(self.zone + "trips/custom-trip/type", b"active\0")
        self.write(self.zone + "trips/custom-trip/temperature", struct.pack(">I",60500))
        with self.assertRaises(support.FanError): self.hw.inspect()
    def test_disabled_or_missing_cpu_protection_is_rejected(self):
        self.write(self.thermal + "mode", b"disabled")
        with self.assertRaisesRegex(support.FanError, "protection"): self.hw.inspect()
        self.write(self.thermal + "mode", b"enabled")
        self.write(self.thermal + "trip_point_2_type", b"active")
        with self.assertRaisesRegex(support.FanError, "critical"): self.hw.inspect()
    def test_chip_phandle_mismatch_is_rejected(self):
        self.write("sys/bus/gpio/devices/gpiochip0/of_node/phandle",struct.pack(">I",99))
        with self.assertRaisesRegex(support.FanError, "matching BCM2711"): self.hw.gpio_info()
    def test_gpio_api_v1_is_rejected_before_unbind(self):
        self.hw.gpio = SimpleNamespace()
        with self.assertRaisesRegex(support.FanError, "version 2"): self.hw.acquire()
        self.assertEqual(self.events, [])
    def test_foreign_owner_is_never_unbound_or_rebound(self):
        self.gpio.consumer = "serial-port"
        for operation in (self.hw.acquire,self.hw.restore):
            with self.assertRaises(support.FanError): operation()
        self.assertEqual(self.events, [])
    def test_off_handoff_low_and_close_restore_native(self):
        self.hw.acquire()
        self.assertEqual(self.events, ["unbind"])
        self.assertFalse(self.hw.output())
        self.assertEqual(self.gpio.requests[0][1]["config"], {14:{"direction":"output", "output_value":0}})
        self.hw.close()
        self.assertEqual(self.events, ["unbind","bind"])
        self.assertEqual(self.gpio.releases,1)
        self.assertTrue(self.hw.inspect()["bound"])
        self.assertEqual((self.root / (self.thermal + "mode")).read_text(),"enabled")
    def test_failed_gpio_request_restores_kernel(self):
        self.gpio.error = OSError("busy")
        with self.assertRaises(OSError): self.hw.acquire()
        self.assertEqual(self.events,["unbind","bind"])
        self.assertTrue(self.hw.inspect()["bound"])
    def test_interrupted_gpio_request_restores_kernel(self):
        self.gpio.error = KeyboardInterrupt()
        with self.assertRaises(KeyboardInterrupt): self.hw.acquire()
        self.assertEqual(self.events,["unbind","bind"])
    def test_sensor_failure_does_not_block_kernel_restore(self):
        self.hw.acquire()
        self.write(self.thermal + "temp", b"unavailable")
        with self.assertRaises(support.FanError): self.hw.inspect()
        self.hw.close()
        self.assertTrue(self.hw.inspect(read_temperature=False)["bound"])
        self.assertEqual(self.events,["unbind","bind"])
    def test_restore_is_idempotent(self):
        self.hw.restore()
        self.assertEqual(self.events,[])
    def test_sample_is_verified_low_and_no_rpm(self):
        self.hw.acquire()
        path = self.root / "state"
        support.publish(self.hw,path,clock=lambda:500)
        value=json.loads(path.read_bytes())
        self.assertEqual(value,{"pid":os.getpid(),"monotonic_ns":500,"output_high":False})
        self.gpio.high=1
        with self.assertRaises(support.FanError): support.publish(self.hw,path)
        self.hw.close()


class ServiceTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name)
        self.unit=self.root / "etc/systemd/system" / cli.UNIT
        self.unit.parent.mkdir(parents=True);self.unit.write_text(support.UNIT_TEXT)
        (self.root / "run/lock").mkdir(parents=True)
        self.statefile=self.root / "run/automations-fan-off/state"
        self.statefile.parent.mkdir()
        self.clock=10_000_000_000
        self.enabled="disabled";self.active="inactive";self.bound=True
        self.consumer="gpio-fan@0";self.pid=0;self.dropins="";self.fail=None;self.calls=[]
        self.system=cli.System(support,self.root,self.runner,lambda:self.clock,os.getuid())
        test=self
        class Hardware:
            device=Path("/sys/bus/platform/devices/gpio-fan@0")
            def inspect(self, read_temperature=True): return dict(on_celsius=60,off_celsius=50,temperature_millidegrees=55000,bound=test.bound)
            def gpio_info(self): return Path("/dev/gpiochip0"),SimpleNamespace(used=True,consumer=test.consumer)
            def kernel_output(self): return False
        self.system.hardware=Hardware()
    def sample(self,pid=123,age=0):
        self.statefile.write_text(json.dumps({"pid":pid,"monotonic_ns":self.clock-age,"output_high":False}))
    def runner(self,args):
        if args[1]=="show":
            return "\n".join(["LoadState=loaded","FragmentPath=/etc/systemd/system/"+cli.UNIT,
                "DropInPaths="+self.dropins,"UnitFileState="+self.enabled,"ActiveState="+self.active,
                "SubState="+("running" if self.active=="active" else "dead"),"MainPID="+str(self.pid)])
        action=args[1];self.calls.append(action)
        if action=="enable":self.enabled="enabled"
        if action=="disable":self.enabled="disabled"
        if action=="start":
            self.active="active";self.bound=False;self.consumer=support.CONSUMER;self.pid=123;self.sample()
        if action in {"stop","restore"}:
            self.active="inactive";self.bound=True;self.consumer="gpio-fan@0";self.pid=0
        if self.fail and self.fail[0]==action:
            error=self.fail[1];self.fail=None;raise error
        return ""
    def test_status_default_auto_reads_actual_state(self):
        result=self.system.observe()
        self.assertEqual((result["live"],result["requested"]),("auto","auto"))
        self.assertFalse(result["output_high"])
    def test_off_then_auto_changes_persistence_and_live_state(self):
        self.assertEqual(cli.change(self.system,"off")["live"],"off")
        self.assertEqual(self.calls,["enable","start"])
        self.assertEqual(cli.change(self.system,"auto")["live"],"auto")
        self.assertEqual(self.calls,["enable","start","stop","restore","disable"])
    def test_repeated_modes_are_idempotent(self):
        cli.change(self.system,"auto");self.assertEqual(self.calls,[])
        cli.change(self.system,"off");self.calls=[]
        cli.change(self.system,"off");self.assertEqual(self.calls,[])
    def test_partial_enable_start_failure_rolls_back(self):
        self.fail=("start",OSError("start failure"))
        with self.assertRaisesRegex(cli.FanError,"previous fan mode was restored"):cli.change(self.system,"off")
        self.assertEqual((self.enabled,self.active,self.bound),("disabled","inactive",True))
    def test_interrupt_after_disable_restores_previous_off_mode(self):
        cli.change(self.system,"off");self.fail=("disable",KeyboardInterrupt())
        with self.assertRaisesRegex(cli.FanError,"previous fan mode was restored"):cli.change(self.system,"auto")
        self.assertEqual((self.enabled,self.active,self.bound),("enabled","active",False))
    def test_incomplete_rollback_is_reported(self):
        original=self.runner
        def broken(args):
            if args[1] in {"start","stop"}:raise OSError("failure")
            return original(args)
        self.system.runner=broken
        with self.assertRaisesRegex(cli.FanError,"rollback is incomplete"):cli.change(self.system,"off")
    def test_failed_holder_reports_kernel_fallback_not_off(self):
        self.enabled="enabled";self.active="failed"
        result=self.system.observe()
        self.assertEqual((result["requested"],result["live"]),("off","auto"))
    def test_stale_or_wrong_pid_snapshot_is_not_live_off(self):
        cli.change(self.system,"off")
        for pid,age in ((124,0),(123,3_000_000_001),(123,-1)):
            self.sample(pid,age)
            self.assertEqual(self.system.observe()["live"],"unavailable")
    def test_foreign_gpio_owner_blocks_mutation(self):
        self.consumer="another-process"
        with self.assertRaisesRegex(cli.FanError,"ownership"):cli.change(self.system,"off")
        self.assertEqual(self.calls,[])
    def test_unknown_unit_text_or_dropin_blocks_changes(self):
        self.dropins="/etc/override.conf"
        with self.assertRaisesRegex(cli.FanError,"override"):cli.change(self.system,"off")
        self.dropins="";self.unit.write_text(support.UNIT_TEXT+"# modified\n")
        with self.assertRaisesRegex(cli.FanError,"supported unit"):cli.change(self.system,"off")
        self.assertEqual(self.calls,[])
    def test_unsafe_unit_symlink_is_rejected(self):
        target=self.unit.with_suffix(".original");self.unit.rename(target);self.unit.symlink_to(target)
        with self.assertRaises(support.FanError):self.system.observe()
    def test_requested_off_kernel_auto_recovery_to_auto(self):
        self.enabled="enabled";self.active="failed"
        self.assertEqual(cli.change(self.system,"auto")["requested"],"auto")
    def test_main_status_error_is_nonzero_but_prints_usable_cpu_metrics(self):
        result=dict(requested="auto",live="unavailable",service="inactive",output_high=None,
                    on_celsius=None,off_celsius=None,cpu_usage_percent=25.0,cpu_sample_seconds=.2,
                    temperature_millidegrees=56000,thermal_mode="enabled",critical_millidegrees=110000,
                    faults=["Fan overlay is missing. Build a configured fan image and reboot first."])
        with patch.object(cli,"load_support",return_value=support), patch.object(cli,"System",return_value=self.system), \
             patch.object(self.system,"status",return_value=result), patch("sys.stdout",new_callable=io.StringIO) as output:
            code=cli.main(["--status"])
        self.assertEqual(code,1)
        self.assertIn("CPU usage: 25.0%",output.getvalue())
        self.assertIn("CPU temperature: 56.0 C",output.getvalue())
        self.assertIn("Fan overlay is missing",output.getvalue())
        self.assertNotIn("kernel automation",output.getvalue())
    def test_process_environment_is_fixed(self):
        with patch.object(cli.subprocess,"run",return_value=SimpleNamespace(returncode=0,stdout="ok")) as run:
            self.assertEqual(cli.run_command(["/usr/bin/systemctl","show"]),"ok")
        self.assertEqual(run.call_args.kwargs["env"],{"PATH":"/usr/sbin:/usr/bin:/sbin:/bin","LC_ALL":"C"})
    def test_help_works_without_installed_hardware_or_root(self):
        result=subprocess.run([sys.executable,str(ROOT/"pi4/python/auto_fan.py"),"--help"],text=True,capture_output=True)
        self.assertEqual(result.returncode,0)
        self.assertIn("--auto",result.stdout);self.assertNotIn("--on ",result.stdout)
    def test_packaged_unit_matches_validated_contract(self):
        self.assertEqual((ROOT/"pi4/components/fan-control/files/automations-fan-off.service").read_text(),support.UNIT_TEXT)
        self.assertIn("Type=notify",support.UNIT_TEXT)
        self.assertIn("ExecStopPost="+support.HELPER+" restore",support.UNIT_TEXT)


    def test_missing_overlay_retains_cpu_telemetry_and_reports_unknown(self):
        cpu = dict(cpu_usage_percent=25.0, cpu_sample_seconds=.2, temperature_millidegrees=61000,
                   thermal_mode="enabled", critical_millidegrees=110000)
        with patch.object(self.system.hardware, "inspect", side_effect=support.FanError("Fan overlay is missing. Build a configured fan image and reboot first.")):
            result = self.system.status(sampler=lambda root: cpu)
        self.assertEqual(result["cpu_usage_percent"],25.0)
        self.assertEqual(result["temperature_millidegrees"],61000)
        self.assertEqual(result["live"],"unavailable")
        self.assertIsNone(result["output_high"])
        self.assertTrue(result["faults"])
        self.assertEqual(self.calls,[])
    def test_missing_binding_retains_verified_thresholds_and_cpu_telemetry(self):
        cpu = dict(cpu_usage_percent=10.0, cpu_sample_seconds=.2, temperature_millidegrees=53000,
                   thermal_mode="enabled", critical_millidegrees=110000)
        with patch.object(self.system.hardware,"gpio_info",side_effect=support.FanError("python3-libgpiod version 2 or newer is required.")):
            result=self.system.status(sampler=lambda root:cpu)
        self.assertEqual(result["on_celsius"],60)
        self.assertEqual(result["off_celsius"],50)
        self.assertEqual(result["temperature_millidegrees"],53000)
        self.assertEqual(result["live"],"unavailable")
        self.assertTrue(result["faults"])
        self.assertEqual(self.calls,[])
    def test_status_fault_prints_cpu_data_without_claiming_fan_off_or_rpm(self):
        result=dict(requested="off",live="unavailable",service="failed",output_high=None,
                    on_celsius=60,off_celsius=50,cpu_usage_percent=12.5,cpu_sample_seconds=.2,
                    temperature_millidegrees=63000,thermal_mode="enabled",critical_millidegrees=110000,
                    faults=["Missing GPIO binding."])
        with patch("sys.stdout",new_callable=io.StringIO) as output:cli.show(result)
        text=output.getvalue()
        self.assertIn("CPU usage: 12.5%",text)
        self.assertIn("CPU temperature: 63.0 C",text)
        self.assertIn("Live control: unknown (fault)",text)
        self.assertIn("GPIO14 commanded output: unknown",text)
        self.assertNotIn("5000",text)
    def test_cooling_hint_is_based_on_actual_off_state_and_threshold(self):
        result=dict(requested="off",live="off",service="active",output_high=False,
                    on_celsius=60,off_celsius=50,temperature_millidegrees=61000)
        with patch("sys.stdout",new_callable=io.StringIO) as output:cli.show(result)
        self.assertIn("OFF overrides the fan-on temperature",output.getvalue())
        result["live"]="unavailable"
        with patch("sys.stdout",new_callable=io.StringIO) as output:cli.show(result)
        self.assertNotIn("OFF overrides",output.getvalue())


class CPUDiagnosticsTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);(self.root/"proc").mkdir()
        self.stat=self.root/"proc/stat"
        self.zone=self.root/"sys/class/thermal/thermal_zone3";self.zone.mkdir(parents=True)
        for key,value in {"type":"cpu-thermal","temp":"53500","mode":"enabled",
                          "trip_point_7_type":"critical","trip_point_7_temp":"110000"}.items():
            (self.zone/key).write_text(value)
    def sample(self,before,after):
        self.stat.write_text(before)
        delays=[]
        def sleep(delay):delays.append(delay);self.stat.write_text(after)
        times=iter([1.0,1.2])
        result=cli.cpu_snapshot(self.root,sleeper=sleep,clock=lambda:next(times))
        self.assertEqual(delays,[.2])
        return result
    def test_real_delta_percent_excludes_guest_double_count(self):
        result=self.sample("cpu 100 0 100 800 0 0 0 0 5 0\n","cpu 120 0 110 860 10 0 0 0 10 0\n")
        self.assertAlmostEqual(result["cpu_usage_percent"],30.0)
        self.assertEqual(result["temperature_millidegrees"],53500)
        self.assertEqual(result["critical_millidegrees"],110000)
    def test_no_counter_progress_is_unavailable_not_zero(self):
        row="cpu 100 0 0 100 0 0 0 0\n"
        self.assertIsNone(self.sample(row,row)["cpu_usage_percent"])
    def test_decreasing_iowait_rejects_inconsistent_sample(self):
        result=self.sample("cpu 100 0 0 800 100 0 0 0\n","cpu 110 0 0 900 99 0 0 0\n")
        self.assertIsNone(result["cpu_usage_percent"])
    def test_malformed_proc_stat_does_not_hide_temperature(self):
        self.stat.write_text("cpu malformed\n")
        result=cli.cpu_snapshot(self.root,sleeper=lambda _:self.fail("should not wait"))
        self.assertIsNone(result["cpu_usage_percent"])
        self.assertEqual(result["temperature_millidegrees"],53500)
    def test_oversize_cpu_row_is_rejected(self):
        self.stat.write_text("cpu "+"1 "*3000)
        with self.assertRaises(ValueError):cli.cpu_ticks(self.stat)
    def test_ambiguous_cpu_temperature_is_not_guessed(self):
        other=self.zone.with_name("thermal_zone4");other.mkdir();(other/"type").write_text("cpu-thermal")
        self.stat.write_text("cpu 1 1 1 1 1 1 1 1\n")
        result=cli.cpu_snapshot(self.root,sleeper=lambda _:None)
        self.assertIsNone(result["temperature_millidegrees"])
    def test_missing_optional_trip_does_not_invent_throttling(self):
        (self.zone/"trip_point_7_temp").unlink()
        self.stat.write_text("cpu 1 1 1 1 1 1 1 1\n")
        result=cli.cpu_snapshot(self.root,sleeper=lambda _:None)
        self.assertEqual(result["temperature_millidegrees"],53500)
        self.assertIsNone(result["critical_millidegrees"])
        self.assertNotIn("throttling",result)
if __name__ == "__main__":unittest.main()
