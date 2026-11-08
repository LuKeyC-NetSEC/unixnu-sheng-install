"""Exercise signature validation, block boundaries, failed publication and layout."""
from dataclasses import replace
import hashlib
import io
import json
import os
from pathlib import Path
import struct
import tempfile
import unittest
from unittest import mock

import rebuild_vroot as tool

DEVICE = (Path(os.environ["UNIXNU_DEVICE"]).resolve() if os.environ.get("UNIXNU_DEVICE") else
          next(parent for parent in Path(__file__).resolve().parents if (parent / "board.toml").is_file()))
POLICIES = DEVICE / "scripts/policies/ipados-27.0.1-24A446"


def synthetic(data):
    table = b"".join(hashlib.sha256(data[i:i + 4096]).digest() for i in range(0, len(data), 4096))
    return tool.Policy(b"synthetic", b"anchor", len(data), (len(data) + 4095) // 4096,
                       hashlib.sha256(data).digest(), hashlib.sha256(table).digest(),
                       "00000000-0000-4000-8000-000000000001", 1), table


class HeaderTests(unittest.TestCase):
    def setUp(self):
        self.header = (POLICIES / "OS/manifest.header.bin").read_bytes()
        self.anchor = (POLICIES / "OS/trusted-key.bin").read_bytes()

    def test_actual_pinned_signatures(self):
        for name in ("OS", "SystemOS"):
            policy = tool.parse_policy((POLICIES / name / "manifest.header.bin").read_bytes(),
                                       (POLICIES / name / "trusted-key.bin").read_bytes())
            self.assertEqual(policy.header[:8], b"VROOT01\0")
            self.assertGreater(policy.block_count, 1_000_000)

    def test_signature_tamper(self):
        data = bytearray(self.header)
        data[-1] ^= 1
        with self.assertRaisesRegex(ValueError, "signature verification"):
            tool.parse_policy(data, self.anchor)

    def test_invalid_layout_and_count_and_anchor(self):
        for offset, value in ((8, 2), (12, 159), (16, 512), (20, 1), (32, 0)):
            data = bytearray(self.header)
            struct.pack_into("<I", data, offset, value)
            with self.assertRaises(ValueError):
                tool.parse_policy(data, self.anchor)
        anchor = bytearray(self.anchor)
        anchor[40] ^= 1
        with self.assertRaisesRegex(ValueError, "trusted-key hash"):
            tool.parse_policy(self.header, anchor)
        with self.assertRaisesRegex(ValueError, "exactly 544"):
            tool.parse_policy(self.header + b"x", self.anchor)


class RebuildTests(unittest.TestCase):
    def test_arbitrary_chunk_boundaries_and_final_partial_block(self):
        data = bytes(range(256)) * 35 + b"end"
        policy, table = synthetic(data)
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "OS"
            tool.rebuild([data[:3], data[3:4097], data[4097:]], policy, output, "fixture")
            self.assertEqual((output / "raw.img").read_bytes(), data)
            self.assertEqual((output / "hashes.bin").read_bytes(), table)
            self.assertEqual((output / "manifest.header.bin").read_bytes(), policy.header)
            self.assertEqual(json.loads((output / "rebuild.json").read_text())["block_count"], 3)

    def test_rejects_short_long_corrupt_and_wrong_table_without_publishing(self):
        data = b"A" * 8192
        policy, _ = synthetic(data)
        cases = [([data[:-1]], policy), ([data + b"x"], policy),
                 ([b"B" + data[1:]], policy), ([data], replace(policy, table_sha256=bytes(32)))]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for index, (blocks, selected) in enumerate(cases):
                output = root / str(index)
                with self.assertRaises(ValueError):
                    tool.rebuild(blocks, selected, output, "fixture")
                self.assertFalse(output.exists())
                self.assertEqual(list(root.iterdir()), [])

    def test_refuses_existing_output(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "OS"
            output.mkdir()
            (output / "keep").write_bytes(b"preserve")
            policy, _ = synthetic(b"x")
            with self.assertRaisesRegex(ValueError, "refusing to replace"):
                tool.rebuild([b"x"], policy, output, "fixture")
            self.assertEqual((output / "keep").read_bytes(), b"preserve")


class PackTests(unittest.TestCase):
    def make_inputs(self, root):
        rows, policies = [], {}
        for name, data in (("OS", b"o" * 8192), ("SystemOS", b"s" * 4096)):
            path = root / name
            policy, _ = synthetic(data)
            tool.rebuild([data], policy, path, "fixture")
            policies[path] = policy
            rows.append((name, path))
        return rows, policies

    def test_v2_layout_has_pure_table_objects_and_correct_manifest(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            inputs, policies = self.make_inputs(root)
            with mock.patch.object(tool, "load_rebuilt", side_effect=lambda p: policies[p]):
                report = tool.pack(inputs, 100, 100 + 4096, 4096, root / "packed")
            image = (root / "packed/userdata-root.img").read_bytes()
            self.assertEqual(image[:8], b"SHNGROOT")
            self.assertEqual(struct.unpack_from("<II", image, 8), (2, 4))
            self.assertEqual(image[4064:4096], hashlib.sha256(image[:4064]).digest())
            self.assertEqual(report["image_sha256"], hashlib.sha256(image).hexdigest())
            for obj, (_, path) in zip(report["objects"], inputs):
                expected = (path / "hashes.bin").read_bytes()
                self.assertEqual(obj["offset"] % tool.MIB, 0)
                self.assertEqual(image[obj["offset"]:obj["offset"] + obj["size"]], expected)
                self.assertEqual(obj["size"], policies[path].block_count * 32)

    def test_capacity_and_modified_input_fail_without_output(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            inputs, policies = self.make_inputs(root)
            with mock.patch.object(tool, "load_rebuilt", side_effect=lambda p: policies[p]):
                with self.assertRaisesRegex(ValueError, "capacity"):
                    tool.pack(inputs, 1, 1, 4096, root / "too-small")
                (inputs[0][1] / "raw.img").write_bytes(b"X" * 8192)
                with self.assertRaisesRegex(ValueError, "signed policy"):
                    tool.pack(inputs, 0, 4096, 4096, root / "corrupt")
            self.assertFalse((root / "too-small").exists())
            self.assertFalse((root / "corrupt").exists())
            self.assertEqual(sorted(p.name for p in root.iterdir()), ["OS", "SystemOS"])


def expand_sparse(data):
    """Independent reader following Android sparse v1, rejecting skipped blocks."""
    (magic, major, minor, file_header, chunk_header, block, total,
     chunks, checksum) = struct.unpack_from("<IHHHHIIII", data)
    if (magic, major, minor, file_header, chunk_header, block, checksum) != (
            0xED26FF3A, 1, 0, 28, 12, 4096, 0):
        raise AssertionError("bad sparse header")
    cursor, output, kinds = 28, bytearray(), []
    for _ in range(chunks):
        kind, reserved, blocks, encoded_size = struct.unpack_from("<HHII", data, cursor)
        if reserved or not blocks:
            raise AssertionError("bad sparse chunk")
        body = data[cursor + 12:cursor + encoded_size]
        if kind == 0xCAC1:
            if len(body) != blocks * block:
                raise AssertionError("bad RAW chunk size")
            output.extend(body)
        elif kind == 0xCAC2:
            if len(body) != 4:
                raise AssertionError("bad FILL chunk size")
            output.extend(body * (blocks * block // 4))
        else:
            raise AssertionError("DONT_CARE/unknown chunks are forbidden")
        kinds.append(kind)
        cursor += encoded_size
    if cursor != len(data) or len(output) != total * block:
        raise AssertionError("sparse bounds mismatch")
    return bytes(output), kinds


class SparseAssemblyTests(unittest.TestCase):
    def test_sparse_roundtrip_for_fragmented_zero_and_nonzero_blocks(self):
        data = bytes(8192) + bytes(range(256)) * 32 + bytes(4096) + b"z" * 4096
        stream = io.BytesIO()
        writer = tool.AndroidSparseWriter(stream, len(data))
        for piece in (data[:1], data[1:4095], data[4095:17001], data[17001:]):
            writer.write(piece)
        writer.finish()
        expanded, kinds = expand_sparse(stream.getvalue())
        self.assertEqual(expanded, data)
        self.assertEqual(writer.expanded_hash.hexdigest(), hashlib.sha256(data).hexdigest())
        self.assertIn(0xCAC1, kinds)
        self.assertIn(0xCAC2, kinds)
        self.assertLess(len(stream.getvalue()), len(data))

    def test_sparse_assembly_matches_raw_pack_byte_for_byte(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            inputs, policies = PackTests().make_inputs(root)
            with mock.patch.object(tool, "load_rebuilt", side_effect=lambda p: policies[p]):
                raw_report = tool.pack(inputs, 0, 4096, 4096, root / "raw-root")
            streaming_inputs = [(name, policies[path], tool.file_blocks(path / "raw.img"))
                                for name, path in inputs]
            sparse_report = tool.assemble_windows(streaming_inputs, 0, 4096, 4096, root / "sparse-root")
            sparse_file = (root / "sparse-root/userdata-root.img").read_bytes()
            expanded, _ = expand_sparse(sparse_file)
            self.assertEqual(expanded, (root / "raw-root/userdata-root.img").read_bytes())
            self.assertEqual(raw_report["image_sha256"], sparse_report["expanded_sha256"])
            self.assertEqual(sparse_report["sparse_sha256"], hashlib.sha256(sparse_file).hexdigest())
            self.assertEqual(sparse_report["sparse_file_bytes"], len(sparse_file))
            self.assertEqual(sparse_report["manifest_sha256"], raw_report["manifest_sha256"])
            self.assertLess(len(sparse_file), len(expanded) // 100)
            self.assertFalse((root / "sparse-root/OS/raw.img").exists())
            for name, path in inputs:
                self.assertEqual((root / "sparse-root" / name / "hashes.bin").read_bytes(),
                                 (path / "hashes.bin").read_bytes())

    def test_failed_stream_never_publishes_sparse_image(self):
        data = b"x" * 4096
        policy, _ = synthetic(data)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with self.assertRaisesRegex(ValueError, "signed policy"):
                tool.assemble_windows([("OS", policy, [data]), ("SystemOS", policy, [b"y" * 4096])],
                                      0, 4096, 4096, root / "bad")
            self.assertEqual(list(root.iterdir()), [])

    def test_clear_tail_encodes_zeros_through_capacity_without_skipped_blocks(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            inputs, policies = PackTests().make_inputs(root)
            streaming_inputs = [(name, policies[path], tool.file_blocks(path / "raw.img"))
                                for name, path in inputs]
            report = tool.assemble_windows(streaming_inputs, 0, 4095, 4096,
                                           root / "first-install", clear_tail=True)
            expanded, kinds = expand_sparse((root / "first-install/userdata-root.img").read_bytes())
            self.assertEqual(len(expanded), 4096 * 4096)
            self.assertEqual(report["expanded_bytes"], report["userdata_bytes"])
            self.assertLess(report["image_bytes"], report["expanded_bytes"])
            self.assertEqual(expanded[report["image_bytes"]:], bytes(len(expanded) - report["image_bytes"]))
            self.assertEqual(report["root_sha256"], hashlib.sha256(expanded[:report["image_bytes"]]).hexdigest())
            self.assertIsNone(report["expanded_sha256"])
            self.assertTrue(report["clears_partition_tail"])
            self.assertNotIn(0xCAC3, kinds)


if __name__ == "__main__":
    unittest.main()
