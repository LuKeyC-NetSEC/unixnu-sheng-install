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


def command(args, cwd):
    subprocess.run([str(arg) for arg in args], cwd=cwd, check=True)


def work_path(workspace):
    return workspace / 'UniXNU' / 'out' / 'sheng' / PROFILE / CONFIG


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
    if sha256(seed) != seed_pin:
        fail('The saved installation seed differs from runtime inputs.')
    if package['runtime']['inputs']['data_ramdisk'] != seed_pin:
        fail('The kernel package and saved Data seed are from different installations.')
    if package['runtime']['data_volume_uuid'] != runtime['data_volume_uuid']:
        fail('The package and runtime Data UUIDs differ.')
    if payload['data_ramdisk_sha256'] != seed_pin:
        fail('The boot payload and saved Data seed are from different installations.')

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
    command(['bash', 'scripts/package.sh', '--os', '27', '--uefi', '../uefi-sheng', '--init-data'], workspace / 'device')
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
    parser.add_argument('operation', choices=('preflight', 'build', 'verify'))
    parser.add_argument('--workspace', type=Path, required=True)
    args = parser.parse_args()
    workspace = args.workspace.resolve()
    {'preflight': preflight, 'build': build, 'verify': verify}[args.operation](workspace)


if __name__ == '__main__':
    try:
        main()
    except (RuntimeError, OSError, KeyError, ValueError, subprocess.CalledProcessError) as error:
        sys.exit(f'first-install: {error}')
