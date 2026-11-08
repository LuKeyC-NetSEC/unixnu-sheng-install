#!/usr/bin/env python3
"""Rebuild pinned VerifiedRoot tables and assemble a first-install root image.

All outputs are host files. This tool never opens a device for writing or runs
adb/fastboot. A signed 544-byte header is preserved; no signing key is needed.
The userdata objects contain hashes only, as ShengUfs readPolicyTable requires.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
import hmac
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tempfile
import uuid

BLOCK = 4096
ZERO_BLOCK = bytes(BLOCK)
MIB = 1 << 20
CHUNK = 8 * MIB
HEADER_BYTES = 544
UNIXNU_REVISION = "5dc00d201496a1e7a72d1f5db23f041eb94ace1c"
SHA256_DER = bytes.fromhex("3031300d060960864801650304020105000420")


@dataclass(frozen=True)
class Policy:
    header: bytes
    anchor: bytes
    image_bytes: int
    block_count: int
    image_sha256: bytes
    table_sha256: bytes
    volume_uuid: str
    generation: int


def require(condition, message):
    if not condition:
        raise ValueError(message)


def parse_policy(header: bytes, anchor: bytes) -> Policy:
    require(len(header) == HEADER_BYTES, "policy header must be exactly 544 bytes")
    require(len(anchor) == 395 and anchor[:8] == b"VROOTKEY", "invalid trusted-key layout")
    (magic, version, header_bytes, block_bytes, flags, image_bytes, count,
     identity, image_hash, table_hash, key_hash, generation) = struct.unpack(
        "<8s4I2Q16s32s32s32sQ", header[:160])
    require((magic, version, header_bytes, block_bytes, flags) ==
            (b"VROOT01\0", 1, 160, BLOCK, 0), "unsupported policy header layout")
    require(image_bytes > 0 and count == (image_bytes + BLOCK - 1) // BLOCK,
            "policy image size/block count mismatch")
    require(identity != bytes(16) and generation > 0, "invalid policy identity/generation")
    require(hmac.compare_digest(hashlib.sha256(anchor).digest(), key_hash),
            "trusted-key hash differs from signed policy")
    modulus = int.from_bytes(anchor[8:392], "big")
    exponent = int.from_bytes(anchor[392:], "big")
    require(modulus.bit_length() == 3072 and modulus % 2 == 1 and exponent == 65537,
            "require a complete RSA3072 public anchor with exponent 65537")
    signature = int.from_bytes(header[160:], "big")
    require(0 < signature < modulus, "RSA signature outside modulus")
    digest_info = SHA256_DER + hashlib.sha256(header[:160]).digest()
    expected = b"\0\1" + b"\xff" * (384 - len(digest_info) - 3) + b"\0" + digest_info
    actual = pow(signature, exponent, modulus).to_bytes(384, "big")
    require(hmac.compare_digest(actual, expected), "RSA3072 PKCS1v1.5 signature verification failed")
    return Policy(header, anchor, image_bytes, count, image_hash, table_hash,
                  str(uuid.UUID(bytes=identity)).upper(), generation)


def file_blocks(path: Path):
    with path.open("rb") as stream:
        yield from iter(lambda: stream.read(CHUNK), b"")


def hash_file(path: Path):
    digest = hashlib.sha256()
    for block in file_blocks(path):
        digest.update(block)
    return digest.hexdigest()


def stage_directory(output: Path):
    require(not output.exists(), f"refusing to replace existing output: {output}")
    output.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix="." + output.name + "-", dir=output.parent))
    require(staging.resolve().parent == output.parent.resolve(), "temporary directory escaped output parent")
    return staging


def discard_staging(staging: Path, output: Path):
    if staging.exists():
        require(staging.resolve().parent == output.parent.resolve() and
                staging.name.startswith("." + output.name + "-"),
                "refusing cleanup outside the named output directory")
        shutil.rmtree(staging)


def write_sparse_file(stream, data):
    if data and data == bytes(len(data)):
        stream.seek(len(data), os.SEEK_CUR)
    else:
        stream.write(data)


def rebuild(blocks, policy: Policy, output: Path, source: str):
    """Consume raw disk bytes and publish one complete directory atomically."""
    staging = stage_directory(output)
    try:
        image_hash, table_hash = hashlib.sha256(), hashlib.sha256()
        length = count = 0
        pending = b""
        with (staging / "raw.img").open("wb") as raw, (staging / "hashes.bin").open("wb") as table:
            for chunk in blocks:
                require(isinstance(chunk, (bytes, bytearray, memoryview)), "decoder returned non-byte data")
                length += len(chunk)
                require(length <= policy.image_bytes, "raw image exceeds signed size")
                image_hash.update(chunk)
                write_sparse_file(raw, chunk)
                data = pending + bytes(chunk)
                complete = len(data) // BLOCK * BLOCK
                view = memoryview(data)
                encoded = b"".join(hashlib.sha256(view[at:at + BLOCK]).digest()
                                   for at in range(0, complete, BLOCK))
                table.write(encoded)
                table_hash.update(encoded)
                count += complete // BLOCK
                pending = data[complete:]
            if pending:
                encoded = hashlib.sha256(pending).digest()
                table.write(encoded)
                table_hash.update(encoded)
                count += 1
            require(length == policy.image_bytes, "raw image ends before signed size")
            require(count == policy.block_count, "rebuilt block count differs from policy")
            require(hmac.compare_digest(image_hash.digest(), policy.image_sha256),
                    "raw image SHA-256 differs from signed policy")
            require(hmac.compare_digest(table_hash.digest(), policy.table_sha256),
                    "rebuilt hash table SHA-256 differs from signed policy")
            raw.truncate(length)
        (staging / "manifest.header.bin").write_bytes(policy.header)
        (staging / "trusted-key.bin").write_bytes(policy.anchor)
        report = dict(source=source, image_bytes=length, image_sha256=image_hash.hexdigest(),
                      block_count=count, table_bytes=count * 32, table_sha256=table_hash.hexdigest(),
                      volume_uuid=policy.volume_uuid, generation=policy.generation,
                      header_sha256=hashlib.sha256(policy.header).hexdigest(),
                      trusted_key_sha256=hashlib.sha256(policy.anchor).hexdigest(),
                      signature_preserved=True, signature_verified=True,
                      block_bytes=BLOCK, hardware_tested=False)
        (staging / "rebuild.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        require(not output.exists(), f"output appeared during rebuild: {output}")
        os.replace(staging, output)
        return report
    finally:
        discard_staging(staging, output)


def load_rebuilt(path: Path):
    policy = parse_policy((path / "manifest.header.bin").read_bytes(),
                          (path / "trusted-key.bin").read_bytes())
    report = json.loads((path / "rebuild.json").read_text(encoding="utf-8"))
    require((path / "raw.img").stat().st_size == policy.image_bytes,
            f"{path}: raw image size differs from signed policy")
    require((path / "hashes.bin").stat().st_size == policy.block_count * 32,
            f"{path}: hash table size differs from signed policy")
    require(report["image_sha256"] == policy.image_sha256.hex() and
            report["table_sha256"] == policy.table_sha256.hex() and
            report["header_sha256"] == hashlib.sha256(policy.header).hexdigest(),
            f"{path}: rebuild report differs from signed policy")
    return policy


def align(value):
    return (value + MIB - 1) // MIB * MIB


def pack(inputs, first_lba: int, last_lba: int, lba_bytes: int, output: Path):
    """Match Unixnu userdata.py v2, using already decoded immutable windows."""
    require(lba_bytes == BLOCK and 0 <= first_lba <= last_lba, "invalid 4096-byte target geometry")
    require([name for name, _ in inputs] == ["OS", "SystemOS"], "require OS then SystemOS inputs")
    policies = [(name, path, load_rebuilt(path)) for name, path in inputs]
    require(policies[0][2].anchor == policies[1][2].anchor, "root policies use different trust anchors")
    cursor, rows = MIB, []
    for name, path, policy in policies:
        rows.append((name, path / "raw.img", cursor, policy.image_bytes, 512, 1, policy.image_sha256))
        cursor += align(policy.image_bytes)
    for name, path, policy in policies:
        size = policy.block_count * 32
        rows.append((name + ".vroot", path / "hashes.bin", cursor, size, BLOCK, 3, policy.table_sha256))
        cursor += align(size)
    capacity = (last_lba - first_lba + 1) * lba_bytes
    require(cursor <= capacity, "userdata image exceeds target partition capacity")
    staging = stage_directory(output)
    try:
        image = staging / "userdata-root.img"
        header = bytearray(BLOCK)
        header[:8] = b"SHNGROOT"
        struct.pack_into("<IIQ", header, 8, 2, len(rows), cursor)
        for index, (name, _, offset, size, block_bytes, flags, digest) in enumerate(rows):
            struct.pack_into("<32sQQII32s40s", header, 24 + index * 128,
                             name.encode("ascii"), offset, size, block_bytes, flags, digest, bytes(40))
        header[4064:] = hashlib.sha256(header[:4064]).digest()
        with image.open("wb") as target:
            target.truncate(cursor)
            for name, path, offset, size, _, _, digest in rows:
                target.seek(offset)
                actual, length = hashlib.sha256(), 0
                for chunk in file_blocks(path):
                    length += len(chunk)
                    require(length <= size, f"{name}: input grew during packing")
                    actual.update(chunk)
                    write_sparse_file(target, chunk)
                require(length == size and hmac.compare_digest(actual.digest(), digest),
                        f"{name}: input bytes differ from signed policy")
            target.seek(0)
            target.write(header)
        def describe(row):
            name, _, offset, size, _, _, digest = row
            return dict(name=name, offset=offset, size=size, sha256=digest.hex())
        report = dict(image_bytes=cursor, image_sha256=hash_file(image),
                      manifest_sha256=hashlib.sha256(header).hexdigest(),
                      windows=[describe(row) for row in rows[:2]],
                      objects=[describe(row) for row in rows[2:]], userdata_bytes=capacity,
                      geometry=dict(first_lba=first_lba, last_lba=last_lba, lba_bytes=lba_bytes),
                      signed_policy_headers={name: hashlib.sha256(policy.header).hexdigest()
                                             for name, _, policy in policies},
                      unixnu_reference_revision=UNIXNU_REVISION, hardware_tested=False)
        (staging / "userdata-root.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        require(not output.exists(), f"output appeared during packing: {output}")
        os.replace(staging, output)
        return report
    finally:
        discard_staging(staging, output)


class AndroidSparseWriter:
    """Encode zeros as FILL(0), never DONT_CARE that could retain old bytes."""
    def __init__(self, stream, expanded_bytes):
        require(expanded_bytes > 0 and expanded_bytes % BLOCK == 0, "sparse size must be block aligned")
        self.stream, self.expected = stream, expanded_bytes
        self.expanded_bytes = self.blocks = self.chunks = self.zero_run = 0
        self.raw, self.pending = bytearray(), b""
        self.expanded_hash = hashlib.sha256()
        self.hash_complete = True
        stream.write(bytes(28))

    def flush_raw(self):
        if self.raw:
            self.stream.write(struct.pack("<HHII", 0xCAC1, 0, len(self.raw) // BLOCK, 12 + len(self.raw)))
            self.stream.write(self.raw)
            self.chunks += 1
            self.raw.clear()

    def flush_zero(self):
        if self.zero_run:
            self.stream.write(struct.pack("<HHII", 0xCAC2, 0, self.zero_run, 16) + bytes(4))
            self.chunks += 1
            self.zero_run = 0

    def write(self, data):
        require(self.hash_complete, "cannot append data after an unhashed zero tail")
        self.expanded_bytes += len(data)
        require(self.expanded_bytes <= self.expected, "sparse stream exceeds declared size")
        self.expanded_hash.update(data)
        buffer = self.pending + bytes(data)
        end = len(buffer) // BLOCK * BLOCK
        for at in range(0, end, BLOCK):
            block = buffer[at:at + BLOCK]
            self.blocks += 1
            if block == ZERO_BLOCK:
                self.flush_raw()
                self.zero_run += 1
            else:
                self.flush_zero()
                self.raw.extend(block)
                if len(self.raw) >= 16 * MIB:
                    self.flush_raw()
        self.pending = buffer[end:]

    def zeros(self, count):
        require(count >= 0, "negative zero padding")
        zero = bytes(min(CHUNK, count))
        while count:
            part = zero[:min(len(zero), count)]
            self.write(part)
            count -= len(part)

    def clear_tail(self, count):
        """Encode an aligned zero tail without reading/hashing hundreds of GiB."""
        require(not self.pending and count >= 0 and count % BLOCK == 0,
                "partition tail must be block aligned")
        require(self.expanded_bytes + count == self.expected, "tail does not end at target capacity")
        if count:
            self.flush_raw()
            self.zero_run += count // BLOCK
            self.blocks += count // BLOCK
            self.expanded_bytes += count
            self.hash_complete = False

    def finish(self):
        require(not self.pending and self.expanded_bytes == self.expected and
                self.blocks == self.expected // BLOCK, "incomplete Android sparse stream")
        self.flush_raw()
        self.flush_zero()
        self.stream.seek(0)
        self.stream.write(struct.pack("<IHHHHIIII", 0xED26FF3A, 1, 0, 28, 12,
                                      BLOCK, self.blocks, self.chunks, 0))


def verified_window(blocks, policy, destination, table):
    image_hash, table_hash = hashlib.sha256(), hashlib.sha256()
    length = count = 0
    pending = b""
    for chunk in blocks:
        length += len(chunk)
        require(length <= policy.image_bytes, "decoded window exceeds signed size")
        image_hash.update(chunk)
        destination.write(chunk)
        data = pending + bytes(chunk)
        end = len(data) // BLOCK * BLOCK
        view = memoryview(data)
        encoded = b"".join(hashlib.sha256(view[at:at + BLOCK]).digest()
                           for at in range(0, end, BLOCK))
        table.write(encoded)
        table_hash.update(encoded)
        count += end // BLOCK
        pending = data[end:]
    if pending:
        encoded = hashlib.sha256(pending).digest()
        table.write(encoded)
        table_hash.update(encoded)
        count += 1
    require(length == policy.image_bytes and count == policy.block_count,
            "decoded window size/block count differs from signed policy")
    require(hmac.compare_digest(image_hash.digest(), policy.image_sha256),
            "decoded window SHA-256 differs from signed policy")
    require(hmac.compare_digest(table_hash.digest(), policy.table_sha256),
            "rebuilt table SHA-256 differs from signed policy")


def assemble_windows(inputs, first_lba, last_lba, lba_bytes, output, clear_tail=False):
    """inputs contains (name, authenticated Policy, raw-byte iterator)."""
    require([name for name, _, _ in inputs] == ["OS", "SystemOS"], "require OS then SystemOS")
    require(lba_bytes == BLOCK and 0 <= first_lba <= last_lba, "invalid 4096-byte target geometry")
    require(inputs[0][1].anchor == inputs[1][1].anchor, "policies have different trusted keys")
    cursor, windows, objects = MIB, [], []
    for name, policy, _ in inputs:
        windows.append(dict(name=name, offset=cursor, size=policy.image_bytes,
                            sha256=policy.image_sha256.hex()))
        cursor += align(policy.image_bytes)
    for name, policy, _ in inputs:
        size = policy.block_count * 32
        objects.append(dict(name=name + ".vroot", offset=cursor, size=size,
                            sha256=policy.table_sha256.hex()))
        cursor += align(size)
    capacity = (last_lba - first_lba + 1) * lba_bytes
    require(cursor <= capacity, "userdata root exceeds target partition capacity")
    expanded_bytes = capacity if clear_tail else cursor
    require(expanded_bytes // BLOCK <= 0xffffffff, "Android sparse v1 block count exceeds 32 bits")
    header = bytearray(BLOCK)
    header[:8] = b"SHNGROOT"
    struct.pack_into("<IIQ", header, 8, 2, 4, cursor)
    for index, row in enumerate(windows + objects):
        struct.pack_into("<32sQQII32s40s", header, 24 + 128 * index, row["name"].encode(),
                         row["offset"], row["size"], 512 if index < 2 else BLOCK,
                         1 if index < 2 else 3, bytes.fromhex(row["sha256"]), bytes(40))
    header[4064:] = hashlib.sha256(header[:4064]).digest()
    staging = stage_directory(output)
    try:
        image = staging / "userdata-root.img"
        with image.open("wb") as stream:
            writer = AndroidSparseWriter(stream, expanded_bytes)
            writer.write(header)
            writer.zeros(MIB - BLOCK)
            for name, policy, blocks in inputs:
                policy_out = staging / name
                policy_out.mkdir()
                (policy_out / "manifest.header.bin").write_bytes(policy.header)
                (policy_out / "trusted-key.bin").write_bytes(policy.anchor)
                with (policy_out / "hashes.bin").open("wb") as table:
                    try:
                        verified_window(blocks, policy, writer, table)
                    finally:
                        if hasattr(blocks, "close"):
                            blocks.close()
                writer.zeros(align(policy.image_bytes) - policy.image_bytes)
            for name, policy, _ in inputs:
                table = staging / name / "hashes.bin"
                for chunk in file_blocks(table):
                    writer.write(chunk)
                writer.zeros(align(policy.block_count * 32) - policy.block_count * 32)
            root_hash = writer.expanded_hash.hexdigest()
            if clear_tail:
                writer.clear_tail(capacity - cursor)
            writer.finish()
            expanded_hash = writer.expanded_hash.hexdigest() if writer.hash_complete else None
        sparse_hash = hash_file(image)
        report = dict(format="android-sparse-v1", image_bytes=cursor,
                      image_sha256=root_hash, root_sha256=root_hash, root_content_sha256=root_hash,
                      expanded_bytes=expanded_bytes, expanded_sha256=expanded_hash,
                      sparse_file_bytes=image.stat().st_size, sparse_sha256=sparse_hash,
                      manifest_sha256=hashlib.sha256(header).hexdigest(),
                      windows=windows, objects=objects, userdata_bytes=capacity,
                      geometry=dict(first_lba=first_lba, last_lba=last_lba, lba_bytes=lba_bytes),
                      signature_verified=True, signature_preserved=True,
                      policy_headers={name: hashlib.sha256(policy.header).hexdigest()
                                      for name, policy, _ in inputs},
                      unixnu_reference_revision=UNIXNU_REVISION, hardware_tested=False,
                      zero_blocks="FILL(0); no DONT_CARE chunks", clears_partition_tail=clear_tail,
                      root_hash_scope="SHNGROOT image_bytes; the optional zero tail is outside this hash")
        (staging / "userdata-root.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        require(not output.exists(), f"output appeared during assembly: {output}")
        os.replace(staging, output)
        return report
    finally:
        discard_staging(staging, output)


def assemble(args):
    revision = subprocess.check_output(["git", "-C", str(args.unixnu), "rev-parse", "HEAD"], text=True).strip()
    require(revision == UNIXNU_REVISION, "UniXNU checkout does not match the reviewed pinned revision")
    sys.path.insert(0, str(args.unixnu.resolve() / "scripts"))
    from unixnu import cli, userdata
    from unixnu.config import Context
    from unixnu.ipsw import Ipsw
    command = ["build", "userdata", "--os", args.os, "-D", str(args.device.resolve())]
    ctx = Context(cli.parser().parse_args(command))
    geometry = ctx.board["userdata"]
    require((args.first_lba, args.last_lba, args.lba_bytes) ==
            (geometry["first_lba"], geometry["last_lba"], geometry.get("lba_bytes", BLOCK)),
            "target geometry differs from selected board; review board configuration before building")
    profile = ctx.work.parent.name
    source = Ipsw(ctx)
    windows = geometry["windows"]
    require([row["name"] for row in windows] == ["OS", "SystemOS"], "unexpected OS profile root windows")
    inputs = []
    for row in windows:
        name = row["name"]
        policy_dir = args.device / "scripts/policies" / profile / name
        policy = parse_policy((policy_dir / "manifest.header.bin").read_bytes(),
                              (policy_dir / "trusted-key.bin").read_bytes())
        dmg = source.disk_image(row["component"])
        inputs.append((name, policy, userdata.disk_blocks(dmg, policy.image_bytes)))
    return assemble_windows(inputs, args.first_lba, args.last_lba, args.lba_bytes,
                            args.output_dir, clear_tail=args.clear_tail)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    rebuild_parser = commands.add_parser("rebuild", help="decode one window and rebuild its authenticated table")
    rebuild_parser.add_argument("--input", type=Path, required=True)
    rebuild_parser.add_argument("--format", choices=("raw", "dmg"), required=True)
    rebuild_parser.add_argument("--policy-dir", type=Path, required=True)
    rebuild_parser.add_argument("--unixnu", type=Path, help="pinned UniXNU checkout; required for DMG decoding")
    rebuild_parser.add_argument("--output-dir", type=Path, required=True)
    pack_parser = commands.add_parser("pack", help="assemble v2 userdata root with the two pure table objects")
    pack_parser.add_argument("--os", type=Path, required=True)
    pack_parser.add_argument("--systemos", type=Path, required=True)
    for name in ("first-lba", "last-lba", "lba-bytes"):
        pack_parser.add_argument("--" + name, type=lambda x: int(x, 0), required=True)
    pack_parser.add_argument("--output-dir", type=Path, required=True)
    assemble_parser = commands.add_parser("assemble", help="stream the cached IPSW windows directly into an Android sparse root")
    assemble_parser.add_argument("--unixnu", type=Path, required=True)
    assemble_parser.add_argument("--device", type=Path, required=True)
    assemble_parser.add_argument("--os", default="27")
    for name in ("first-lba", "last-lba", "lba-bytes"):
        assemble_parser.add_argument("--" + name, type=lambda x: int(x, 0), required=True)
    assemble_parser.add_argument("--output-dir", type=Path, required=True)
    assemble_parser.add_argument("--clear-tail", action="store_true",
                                 help="first installation: encode FILL(0) through the end of userdata")
    args = parser.parse_args(argv)
    try:
        if args.command == "rebuild":
            policy = parse_policy((args.policy_dir / "manifest.header.bin").read_bytes(),
                                  (args.policy_dir / "trusted-key.bin").read_bytes())
            if args.format == "raw":
                blocks = file_blocks(args.input)
            else:
                require(args.unixnu is not None, "--format dmg requires --unixnu")
                sys.path.insert(0, str(args.unixnu.resolve() / "scripts"))
                from unixnu import userdata
                blocks = userdata.disk_blocks(args.input, policy.image_bytes)
            try:
                report = rebuild(blocks, policy, args.output_dir, str(args.input.resolve()))
            finally:
                if hasattr(blocks, "close"):
                    blocks.close()
        elif args.command == "pack":
            report = pack([("OS", args.os), ("SystemOS", args.systemos)], args.first_lba,
                          args.last_lba, args.lba_bytes, args.output_dir)
        else:
            report = assemble(args)
        print(json.dumps(report, indent=2))
    except (OSError, ValueError, KeyError) as exc:
        parser.exit(1, f"ERROR: {exc}\n")


if __name__ == "__main__":
    main()
