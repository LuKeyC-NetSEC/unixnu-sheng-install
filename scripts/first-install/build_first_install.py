#!/usr/bin/env python3
"""Build and validate this first-install image set without accessing a tablet."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import struct
import subprocess
import sys
import tomllib


PROFILE = 'ipados-27.0.1-24A446'
CONFIG = 'sheng_ipados27'
PINS = {
    'device': '689400177f93219a38bd7cf5ae2e9f5782adc594',
    'UniXNU': '82b847c4ac3f68a57024b3082ffa3a03442defd9',
    'uefi-sheng': '66421cb7bb5694843aec8de1ca3d1de4c20cca38',
}
FIRST_LBA = 3094592
LAST_LBA = 64007162
LBA_BYTES = 4096
USERDATA_BYTES = 249497890816
BOOT_BYTES = 201326592
ORIGINAL_SEED_SHA256 = '8359108a2ac862b6bb3e6cd6398a506bdd16345ccc15bfc844005672cc44bb0b'
OS_DISK_IMAGE = '043-68950-668.dmg'
SMALL_CACHE_LIMIT = 256 * 1024 ** 2
OS_CACHE_LIMIT = 8 * 1024 ** 3
OVERLAY = {
    'path': 'patches/mesa/turnip-frame-diagnostics.patch',
    'before_sha256': '5eb8dda6e381f10fa48b62a9a497fb74a8b08c7999dea5468585c9848b2af966',
    'after_sha256': 'cd15bbb8f932d564a99300e63d3d6c5a6a714b311596e80619092c5d3fa5e25a',
    'reason': 'Declare the first new-file diff as mode 100644 so git apply does not treat /dev/null as a source path; hunk bytes are unchanged.',
}


def fail(message):
    raise RuntimeError(message)


def sha256(path):
    digest = hashlib.sha256()
    with Path(path).open('rb') as handle:
        for chunk in iter(lambda: handle.read(8 * 1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


def read_json(path):
    return json.loads(Path(path).read_text(encoding='utf-8'))


def redact(text):
    for name in ('UNIXNU_UNIQUE_CHIP_ID', 'GITHUB_TOKEN', 'GH_TOKEN'):
        value = os.environ.get(name, '')
        if value:
            text = re.sub(re.escape(value), '[secret redacted]', text, flags=re.IGNORECASE)
    text = re.sub(r'\b(?:gh[pousr]_[A-Za-z0-9_]+|github_pat_[A-Za-z0-9_]+)\b', '[credential redacted]', text)
    text = re.sub(r'base64:[A-Za-z0-9+/=]+', '[key redacted]', text)
    return re.sub(r'https?://[^\s<>"\']+', lambda match: match.group(0).split('?', 1)[0] +
                  ('?[query redacted]' if '?' in match.group(0) else ''), text)


def command(args, cwd, log_file=None):
    argv = [str(arg) for arg in args]
    if log_file is None:
        subprocess.run(argv, cwd=cwd, check=True)
        return
    log_file.parent.mkdir(parents=True, exist_ok=True)
    with log_file.open('x', encoding='utf-8') as output:
        process = subprocess.Popen(argv, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        for raw in iter(lambda: process.stdout.readline(1024 * 1024), b''):
            text = redact(raw.decode('utf-8', errors='replace'))
            output.write(text)
            print(text, end='', flush=True)
        result = process.wait()
    if result:
        raise subprocess.CalledProcessError(result, argv)


def work_path(workspace):
    return workspace / 'UniXNU' / 'out' / 'sheng' / PROFILE / CONFIG


def preserved_seed(workspace):
    run = os.environ.get('PRESERVED_SEED_RUN_ID', '')
    if not run.isdigit() or int(run) <= 0:
        fail('A prior run containing the original installation seed is required; this retry never creates a new seed.')
    source = workspace / 'preserved-seed' / 'data.dbr'
    if not source.is_file() or source.is_symlink() or sha256(source) != ORIGINAL_SEED_SHA256:
        fail('The downloaded Data seed differs from the verified original installation seed.')
    return source


def restore_seed(workspace):
    source = preserved_seed(workspace)
    target = work_path(workspace) / 'runtime' / 'data.dbr'
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.exists():
        if target.is_symlink() or sha256(target) != ORIGINAL_SEED_SHA256:
            fail('An existing runtime seed differs; refusing replacement.')
    else:
        with source.open('rb') as incoming, target.open('xb') as output:
            shutil.copyfileobj(incoming, output, 512 * 1024)
    if sha256(target) != ORIGINAL_SEED_SHA256:
        fail('Restored runtime seed hash differs from the verified original.')
    return target


def apply_overlay(workspace):
    target = workspace / 'UniXNU' / OVERLAY['path']
    before = target.read_bytes()
    if hashlib.sha256(before).hexdigest() != OVERLAY['before_sha256']:
        fail('The reviewed Mesa patch overlay input differs from its pinned hash.')
    first, separator, rest = before.partition(b'\n')
    if not separator or not first.startswith(b'diff --git ') or rest.startswith(b'new file mode '):
        fail('The reviewed Mesa new-file metadata overlay no longer applies exactly.')
    after = first + b'\nnew file mode 100644\n' + rest
    if hashlib.sha256(after).hexdigest() != OVERLAY['after_sha256']:
        fail('The reviewed Mesa patch overlay output differs from its pinned hash.')
    target.write_bytes(after)
    return [dict(OVERLAY)]


def cache_record(path):
    if not path.is_file() or path.is_symlink() or path.stat().st_size > 64 * 1024:
        return None
    try:
        data = read_json(path)
    except (ValueError, OSError):
        return None
    allowed = {'member', 'size', 'bytes', 'sha256', 'aea_sha256'}
    if not isinstance(data, dict) or set(data) - allowed:
        return None
    if any(not isinstance(value, (str, int)) for value in data.values()):
        return None
    if any(isinstance(value, str) and ('://' in value or '?' in value or 'token' in value.lower()) for value in data.values()):
        return None
    return data


def copy_cache_file(source, target):
    if source.is_symlink() or not source.is_file():
        fail('IPSW cache contains a link or missing file.')
    if target.exists():
        if target.is_symlink() or sha256(target) != sha256(source):
            fail('IPSW cache conflicts with a local file; refusing replacement.')
        return
    target.parent.mkdir(parents=True, exist_ok=True)
    with source.open('rb') as incoming, target.open('xb') as output:
        shutil.copyfileobj(incoming, output, 512 * 1024)


def restore_cache(workspace):
    target = workspace / 'UniXNU' / 'out' / 'ipsw' / '24A446'
    for name in ('ipsw-small', 'ipsw-os'):
        source = workspace / '.first-install-cache' / name
        if not source.is_dir() or source.is_symlink():
            continue
        for record in source.glob('*.json'):
            metadata = cache_record(record)
            if metadata is None:
                fail('Restored IPSW cache metadata contains unexpected fields or values.')
            copy_cache_file(record, target / record.name)
            payload = record.with_suffix('')
            if payload.is_file():
                if sha256(payload) != metadata.get('sha256'):
                    fail('Restored IPSW cache payload differs from its recorded hash.')
                copy_cache_file(payload, target / payload.name)


def collect_cache(workspace):
    source = workspace / 'UniXNU' / 'out' / 'ipsw' / '24A446'
    if not source.is_dir():
        return
    output = workspace / '.first-install-cache'
    small_total = 0
    for payload in sorted(source.iterdir()):
        if (not payload.is_file() or payload.is_symlink() or
                not (payload.suffix in ('.im4p', '.trustcache', '.im4m') or payload.name.startswith(('kernelcache.', 'DeviceTree.')))):
            continue
        size = payload.stat().st_size
        record = payload.with_suffix(payload.suffix + '.json')
        metadata = cache_record(record)
        if metadata is None or small_total + size + record.stat().st_size > SMALL_CACHE_LIMIT:
            continue
        if sha256(payload) != metadata.get('sha256'):
            fail('IPSW small cache payload differs from its recorded hash.')
        target = output / 'ipsw-small'
        copy_cache_file(payload, target / payload.name)
        copy_cache_file(record, target / record.name)
        small_total += size + record.stat().st_size
    if os.environ.get('CACHE_DECRYPTED_OS', '').lower() == 'true':
        payload = source / OS_DISK_IMAGE
        record = payload.with_suffix(payload.suffix + '.json')
        origin = payload.with_suffix(payload.suffix + '.aea.json')
        metadata, archive = cache_record(record), cache_record(origin)
        if payload.is_file() and not payload.is_symlink() and metadata and archive:
            if payload.stat().st_size > OS_CACHE_LIMIT:
                print('Decrypted OS cache skipped because it exceeds the optional 8 GiB limit.')
            elif (sha256(payload) != metadata.get('sha256') or metadata.get('aea_sha256') != archive.get('sha256')):
                fail('Decrypted OS cache identities do not match.')
            else:
                for item in (payload, record, origin):
                    copy_cache_file(item, output / 'ipsw-os' / item.name)
    print(f'Prepared at most {SMALL_CACHE_LIMIT // 1024 ** 2} MiB of public IPSW members; decrypted OS caching is explicit opt-in.')


def collect_logs(workspace):
    target = workspace / 'redacted-build-logs'
    target.mkdir(exist_ok=True)
    sources = []
    package_log = workspace / 'installation-evidence' / 'package.stdout.log'
    if package_log.is_file():
        sources.append(package_log)
    directory = work_path(workspace) / 'logs'
    if directory.is_dir():
        sources += sorted(path for path in directory.glob('*.log') if path.is_file() and not path.is_symlink())
    total = 0
    for index, source in enumerate(sources):
        if total >= 32 * 1024 ** 2:
            break
        limit = min(8 * 1024 ** 2, 32 * 1024 ** 2 - total)
        with source.open('rb') as incoming:
            if source.stat().st_size > limit:
                incoming.seek(-limit, os.SEEK_END)
                body = '[Earlier log content omitted to keep this diagnostic artifact bounded.]\n'
            else:
                body = ''
            body += incoming.read(limit).decode('utf-8', errors='replace')
        data = redact(body).encode('utf-8')
        (target / f'{index:02}-{source.name}').write_bytes(data)
        total += len(data)
    patch = workspace / 'UniXNU' / OVERLAY['path']
    applied = [OVERLAY] if patch.is_file() and sha256(patch) == OVERLAY['after_sha256'] else []
    (target / 'context.json').write_text(json.dumps({
        'source_revisions': PINS, 'original_seed_sha256': ORIGINAL_SEED_SHA256,
        'preserved_seed_run_id': os.environ.get('PRESERVED_SEED_RUN_ID', ''),
        'source_overlays': applied, 'diagnostic_bytes': total,
    }, indent=2) + '\n', encoding='utf-8')


def preflight(workspace):
    if platform.system() != 'Darwin':
        fail('The selected AEA and Data seed preparation requires macOS.')
    seed = os.environ.get('UNIXNU_UNIQUE_CHIP_ID', '')
    if not re.fullmatch(r'[0-9a-fA-F]{8}', seed):
        fail('Set the UNIXNU_UNIQUE_CHIP_ID repository secret to an eight-digit hexadecimal installation identity.')
    for directory, pin in PINS.items():
        path = workspace / directory
        actual = subprocess.check_output(['git', '-C', str(path), 'rev-parse', 'HEAD'], text=True).strip()
        if actual != pin:
            fail(f'{directory}: source revision differs from the reviewed pin.')
    board = tomllib.loads((workspace / 'device' / 'board.toml').read_text(encoding='utf-8'))
    if board['board']['name'] != 'sheng' or board['board']['os_profile'] != PROFILE:
        fail('Unexpected device or OS profile.')
    geometry = board['userdata']
    if (geometry['first_lba'], geometry['last_lba'], geometry['lba_bytes']) != (FIRST_LBA, LAST_LBA, LBA_BYTES):
        fail('Reference userdata geometry differs from the reviewed source.')
    if (LAST_LBA - FIRST_LBA + 1) * LBA_BYTES != USERDATA_BYTES:
        fail('Reference userdata capacity differs from the fastboot measurement.')
    helper = Path(__file__).with_name('rebuild_vroot.py')
    if not helper.is_file():
        fail('Missing reviewed rebuild_vroot.py helper.')
    preserved_seed(workspace)
    print('Source revisions, target profile and measured partition capacity match the installation plan.')
    print('The start/end LBA values are source references; direct GPT confirmation is still required before flashing.')
    print(f'Available disk space: {shutil.disk_usage(workspace).free / 2**30:.1f} GiB')


def verify(workspace):
    work = work_path(workspace)
    package = read_json(work / 'package.manifest.json')
    if package['device'] != 'sheng' or package['os_profile'] != PROFILE:
        fail('The package manifest targets another device or OS.')
    boot = work / 'boot' / 'boot.img'
    if not 0 < boot.stat().st_size <= BOOT_BYTES:
        fail('The boot image does not fit the measured 192 MiB boot partition.')
    boot_pin = package['outputs']['boot.img']
    if boot_pin['bytes'] != boot.stat().st_size or boot_pin['sha256'] != sha256(boot):
        fail('The boot image differs from its package manifest.')
    boot_report = read_json(work / 'boot' / 'boot.json')
    if not boot_report.get('ramdisk_bytes', 0):
        fail('The boot image has no payload ramdisk.')
    payload = read_json(work / 'payload' / 'payload.json')
    arguments = payload['kernel_args']
    if isinstance(arguments, str):
        arguments = arguments.split()
    if any(arg.split('=', 1)[0] in {'sheng-autoreset', 'sheng-data-reset'} for arg in arguments):
        fail('The normal installation image carries an automatic reset or Data reset argument.')
    if package['kernel_command_line_bytes'] >= 1000:
        fail('The kernel command line exceeds the package limit.')

    runtime = read_json(work / 'runtime' / 'inputs.json')
    seed = work / 'runtime' / 'data.dbr'
    seed_pin = runtime['inputs']['data_ramdisk']['sha256']
    if seed_pin != ORIGINAL_SEED_SHA256:
        fail('Runtime selected another installation seed; refusing changed Data identity.')
    if sha256(seed) != seed_pin:
        fail('The saved installation seed differs from runtime inputs.')
    if package['runtime']['inputs']['data_ramdisk'] != seed_pin:
        fail('The kernel package and saved Data seed are from different installations.')
    if package['runtime']['data_volume_uuid'] != runtime['data_volume_uuid']:
        fail('The package and runtime Data UUIDs differ.')
    if payload['data_ramdisk_sha256'] != seed_pin:
        fail('The boot payload and saved Data seed are from different installations.')
    if sha256(workspace / 'UniXNU' / OVERLAY['path']) != OVERLAY['after_sha256']:
        fail('The reviewed Mesa metadata overlay is missing or has changed.')

    root_dir = work / 'userdata-first-install'
    root_image = root_dir / 'userdata-root.img'
    root = read_json(root_dir / 'userdata-root.json')
    if root['userdata_bytes'] != USERDATA_BYTES or not 0 < root['image_bytes'] <= USERDATA_BYTES:
        fail('The root image has an invalid partition capacity or expanded length.')
    if root['sparse_file_bytes'] != root_image.stat().st_size or root['sparse_sha256'] != sha256(root_image):
        fail('The Android sparse root image differs from its report.')
    if root['signature_verified'] is not True or root['signature_preserved'] is not True:
        fail('The signed policy headers were not authenticated and preserved.')
    if root['clears_partition_tail'] is not True or root['expanded_bytes'] != USERDATA_BYTES:
        fail('The first-install sparse image does not explicitly clear the complete userdata tail.')
    windows = {item['name']: item for item in root['windows']}
    objects = {item['name']: item for item in root['objects']}
    if set(windows) != {'OS', 'SystemOS'} or set(objects) != {'OS.vroot', 'SystemOS.vroot'}:
        fail('The root image does not contain both OS windows and both authenticated hash tables.')
    for name in ('OS', 'SystemOS'):
        policy = workspace / 'device' / 'scripts' / 'policies' / PROFILE / name
        expected = read_json(policy / 'verification.json')
        if windows[name]['sha256'] != expected['image_sha256']:
            fail(f'{name}: the installed window differs from the signed source policy.')
        header = (policy / 'manifest.header.bin').read_bytes()
        if len(header) != 544:
            fail(f'{name}: unexpected signed root policy header length.')
        table = objects[name + '.vroot']
        if table['size'] != struct.unpack_from('<Q', header, 32)[0] * 32 or table['sha256'] != header[88:120].hex():
            fail(f'{name}: installed hash table differs from the signed policy.')

    files = {'boot.img': boot, 'userdata-root.img': root_image, 'data.dbr': seed}
    result = {
        'device': 'sheng',
        'os_profile': PROFILE,
        'source_revisions': PINS,
        'source_overlays': [dict(OVERLAY)],
        'preserved_seed_run_id': os.environ.get('PRESERVED_SEED_RUN_ID', ''),
        'original_seed_sha256': ORIGINAL_SEED_SHA256,
        'partition_measurements': {
            'userdata_bytes': USERDATA_BYTES,
            'boot_partition_bytes': BOOT_BYTES,
            'logical_block_bytes': LBA_BYTES,
            'source': 'fastboot read-only preflight',
            'reference_first_lba': FIRST_LBA,
            'reference_last_lba': LAST_LBA,
            'start_and_end_lba_directly_verified': False,
        },
        'outputs': {name: {'bytes': path.stat().st_size, 'sha256': sha256(path)} for name, path in files.items()},
        'userdata_root_content_bytes': root['image_bytes'],
        'userdata_root_content_sha256': root['image_sha256'],
        'userdata_expanded_bytes': root['expanded_bytes'],
        'userdata_expanded_sha256': root['expanded_sha256'],
        'userdata_hash_scope': root['root_hash_scope'],
        'userdata_tail_cleared': True,
        'userdata_manifest_sha256': root['manifest_sha256'],
        'signed_root_policy_verified': True,
        'data_volume_uuid': runtime['data_volume_uuid'],
        'hardware_tested': False,
        'device_partitions_written': False,
    }
    evidence = workspace / 'installation-evidence'
    evidence.mkdir(exist_ok=True)
    target = evidence / 'installation.json'
    target.write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
    print('Boot size, package hashes, installation seed and authenticated userdata reports passed validation.')
    return target


def build(workspace):
    preflight(workspace)
    restore_cache(workspace)
    seed = restore_seed(workspace)
    apply_overlay(workspace)
    command(['bash', 'scripts/package.sh', '--os', '27', '--uefi', '../uefi-sheng', '--data-ramdisk', seed],
            workspace / 'device', log_file=workspace / 'installation-evidence' / 'package.stdout.log')
    target = work_path(workspace) / 'userdata-first-install'
    command([
        sys.executable, Path(__file__).with_name('rebuild_vroot.py'), 'assemble',
        '--unixnu', workspace / 'UniXNU', '--device', workspace / 'device', '--os', '27',
        '--first-lba', FIRST_LBA, '--last-lba', LAST_LBA, '--lba-bytes', LBA_BYTES,
        '--output-dir', target, '--clear-tail',
    ], workspace)
    verify(workspace)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation', choices=('preflight', 'build', 'verify', 'collect-cache', 'collect-logs'))
    parser.add_argument('--workspace', type=Path, required=True)
    args = parser.parse_args()
    workspace = args.workspace.resolve()
    {'preflight': preflight, 'build': build, 'verify': verify,
     'collect-cache': collect_cache, 'collect-logs': collect_logs}[args.operation](workspace)


if __name__ == '__main__':
    try:
        main()
    except (RuntimeError, OSError, KeyError, ValueError, subprocess.CalledProcessError) as error:
        sys.exit(f'first-install: {error}')
