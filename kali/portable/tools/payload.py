#!/usr/bin/python3
"""Select an explicit portable Kali-host payload without Pi4 boot or global network policies."""
from __future__ import annotations
import argparse
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import tarfile

ROOT = Path(__file__).resolve().parents[2]
BACKENDS = {'ap-control': 'ap', 'cert-control': 'cert', 'fan-control': 'fan',
            'share-control': 'share', 'ssh-control': 'ssh', 'tor-control': 'tor', 'wifi-control': 'wifi'}
EXCLUDED = {
    'pi4/python/wifi_autoconnect.py',
    'pi4/components/wifi-control/files/automations-wifi-policy.service',
    'pi4/components/wifi-control/files/20-automations-wifi-policy.conf',
    'pi4/python/share_refresh.py',
    'pi4/components/share-control/files/automations-share-watch.service',
    'pi4/components/share-control/files/automations-share-watch.timer',
    'pi4/python/fan_off.py', 'pi4/components/fan-control/files/automations-fan-off.service',
    'pi4/python/auto_hotspot.py', 'pi4/components/hotspot-control/files/automations-hotspot.service',
    'pi4/python/egress.py',
    'pi4/components/tor-control/files/torrc',
    'pi4/components/tor-control/files/automations-tor.service',
    'pi4/components/tor-control/files/automations-tor-recovery.service',
}
EXTRA = {
    'ap-control': [('portable/python/host_ap.py', 'usr/local/libexec/automations-host/ap', '0755')],
    'cert-control': [
        ('portable/python/host_cert.py', 'usr/local/libexec/automations-host/cert', '0755'),
        ('portable/components/cert-control/files/automations-host-cert.service', 'etc/systemd/system/automations-host-cert.service', '0644')],
    'fan-control': [('portable/python/host_fan.py', 'usr/local/libexec/automations-host/fan', '0755')],
    'hotspot-control': [
        ('portable/python/host_ap.py', 'usr/local/libexec/automations-support/host_ap.py', '0644'),
        ('portable/components/hotspot-control/files/completion', 'usr/local/share/automations/completions/share-ap-vm', '0644')],
    'anonymity-runtime': [('portable/python/host_egress.py', 'usr/local/libexec/automations-support/host_egress.py', '0644')],
    'tor-control': [
        ('portable/components/tor-control/files/completion', 'usr/local/share/automations/completions/tor-vm', '0644'),
        ('portable/python/host_tor.py', 'usr/local/libexec/automations-host/tor', '0755'),
        ('portable/components/tor-control/files/torrc', 'usr/local/share/automations/tor/torrc-vm', '0644'),
        ('portable/components/tor-control/files/automations-tor.service', 'etc/systemd/system/automations-tor.service', '0644'),
        ('portable/components/tor-control/files/automations-tor-recovery.service', 'etc/systemd/system/automations-tor-recovery.service', '0644'),
    ],
}
PACKAGES = ['python3', 'python3-dbus', 'python3-gi', 'bash', 'bash-completion', 'zsh',
            'network-manager', 'iw', 'iproute2', 'nftables', 'openssh-server', 'systemd',
            'tor', 'conntrack', 'ca-certificates', 'dnsmasq-base', 'openssl']


def payload(root=ROOT):
    root = Path(root).resolve(strict=True)
    files, components = {}, []
    for path in sorted((root / 'common/components').glob('*/component.json')):
        component = json.loads(path.read_text())
        name = component['id']
        if name == 'proxy-control':
            continue
        entries = [item for item in component['files'] if item['source'] not in EXCLUDED]
        entries += [dict(source=s, destination=d, mode=m) for s, d, m in EXTRA.get(name, ())]
        components.append(dict(id=name, version=component['version']))
        for item in entries:
            item = {key: item[key] for key in ('source', 'destination', 'mode')}
            source, destination = (PurePosixPath(item[key]) for key in ('source', 'destination'))
            if (source.is_absolute() or destination.is_absolute() or '..' in source.parts
                    or '..' in destination.parts or item['mode'] not in ('0644', '0755')):
                raise ValueError('Unsafe VM payload entry.')
            target = root / source
            if target.is_symlink() or not target.is_file() or not target.resolve().is_relative_to(root):
                raise ValueError('VM payload must use existing regular source files: ' + str(source))
            item.update(sha256=hashlib.sha256(target.read_bytes()).hexdigest(), component=name)
            previous = files.get(str(destination))
            if previous is not None:
                # Existing manifests may already carry their matching host backend.
                if any(previous[key] != item[key] for key in ('source', 'mode', 'sha256')):
                    raise ValueError('Conflicting VM destination: ' + str(destination))
            else:
                files[str(destination)] = item
    for component, command in BACKENDS.items():
        if 'usr/local/libexec/automations-host/' + command not in files:
            raise ValueError('Missing VM backend: ' + command)
    return dict(schema_version=1, platform='kali-host', packages=PACKAGES,
                components=components, files=[files[key] for key in sorted(files)],
                excluded_pi4_sources=sorted(EXCLUDED))


def archive(output, root=ROOT):
    manifest = payload(root)
    contents = {'vm-deployment.json': (json.dumps(manifest, indent=2) + '\n').encode()}
    contents.update({item['source']: (root / item['source']).read_bytes() for item in manifest['files']})
    with tarfile.open(output, 'w') as bundle:
        for name, data in sorted(contents.items()):
            info = tarfile.TarInfo(name)
            info.size, info.mode, info.mtime = len(data), 0o644, 0
            info.uid = info.gid = 0
            bundle.addfile(info, io.BytesIO(data))
    return manifest


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--archive', type=Path)
    args = parser.parse_args(argv)
    manifest = archive(args.archive) if args.archive else payload()
    print(json.dumps(manifest, indent=2))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
