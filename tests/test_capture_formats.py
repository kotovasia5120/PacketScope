import json
import unittest

from packetscope.capture_formats import (
    BOUNDARY_KIND,
    NormalizedMessageCollection,
    RawMessage,
    dumps_jsonl,
    parse_can,
    parse_jsonl,
    parse_uart,
)
from packetscope.errors import FormatError, InputLimitError
from packetscope.models import Limits


class CaptureFormatTests(unittest.TestCase):
    def test_jsonl_preserves_messages_and_has_deterministic_round_trip(self):
        source = (
            b'{"timestamp":2,"direction":"tx","source":"uart0",'
            b'"raw":"AAEC","metadata":{"note":"second"}}\n'
            b'\n'
            b'{"timestamp":1.25,"direction":"rx","source":"uart0",'
            b'"raw":"/w==","boundary":"explicit-record"}\n'
        )
        result = parse_jsonl(source, "messages.jsonl")
        self.assertEqual(result.format, "jsonl")
        self.assertEqual([message.timestamp for message in result.messages], [2, 1.25])
        self.assertEqual([message.direction for message in result.messages], ["tx", "rx"])
        self.assertEqual([message.raw for message in result.messages], [b"\x00\x01\x02", b"\xff"])
        self.assertEqual([message.source_identity for message in result.messages], ["uart0", "uart0"])
        self.assertTrue(all(message.boundary == BOUNDARY_KIND for message in result.messages))
        encoded = dumps_jsonl(result)
        self.assertEqual(encoded, dumps_jsonl(parse_jsonl(encoded.encode("utf-8"))))
        self.assertEqual(
            json.loads(encoded.splitlines()[0]),
            {
                "boundary": BOUNDARY_KIND,
                "direction": "tx",
                "index": 0,
                "metadata": {"note": "second"},
                "raw": "AAEC",
                "raw_encoding": "base64",
                "source": "uart0",
                "timestamp": 2,
            },
        )

    def test_jsonl_does_not_infer_framing(self):
        result = parse_jsonl(
            b'{"timestamp":0,"direction":"rx","source":"usb:1-2",'
            b'"raw":"AQIDBA=="}\n'
        )
        self.assertEqual(len(result.messages), 1)
        self.assertEqual(result.messages[0].raw, b"\x01\x02\x03\x04")

    def test_jsonl_rejects_malformed_records(self):
        invalid_records = [
            b"not json\n",
            b'{"timestamp":0,"direction":"rx","source":"s","raw":"not base64"}\n',
            b'{"timestamp":NaN,"direction":"rx","source":"s","raw":""}\n',
            b'{"timestamp":0,"direction":"rx","source":"s"}\n',
            b'{"timestamp":0,"direction":"rx","source":"s","raw":"",'
            b'"boundary":"guessed"}\n',
            b'{"timestamp":0,"direction":"rx","source":"s","raw":"",'
            b'"raw_encoding":"hex"}\n',
            b'{"timestamp":0,"direction":"rx","source":"s","raw":"",'
            b'"raw":""}\n',
            b'{"timestamp":"later","direction":"rx","source":"s","raw":""}\n',
            b'{"timestamp":0,"direction":"","source":"s","raw":""}\n',
        ]
        for invalid in invalid_records:
            with self.subTest(invalid=invalid):
                with self.assertRaises(FormatError):
                    parse_jsonl(invalid)

    def test_jsonl_limits_apply_to_input_messages_bytes_and_output(self):
        with self.assertRaises(InputLimitError):
            parse_jsonl(b"{}\n", limits=Limits(max_input_bytes=1))
        record = b'{"timestamp":0,"direction":"rx","source":"s","raw":"AA=="}\n'
        with self.assertRaises(InputLimitError):
            parse_jsonl(record + record, limits=Limits(max_packets=1))
        with self.assertRaises(InputLimitError):
            parse_jsonl(
                b'{"timestamp":0,"direction":"rx","source":"s","raw":"AAEC"}\n',
                limits=Limits(max_packet_bytes=2),
            )
        collection = parse_jsonl(record)
        with self.assertRaises(InputLimitError):
            collection.to_jsonl(Limits(max_response_bytes=1))

    def test_uart_lines_keep_explicit_line_boundaries(self):
        result = parse_uart(
            b"1.5\trx\tserial:/dev/ttyUSB0\tAAEC\n"
            b"2\ttx\tserial:/dev/ttyUSB0\t/w==\n"
        )
        self.assertEqual(result.format, "uart-lines")
        self.assertEqual([message.raw for message in result.messages], [b"\x00\x01\x02", b"\xff"])
        self.assertEqual([message.timestamp for message in result.messages], [1.5, 2])
        with self.assertRaises(FormatError):
            parse_uart(b"1.0\trx\tserial0\tAA==\tunexpected\n")
        with self.assertRaises(FormatError):
            parse_uart(b"1.0\t\tserial0\tAA==\n")

    def test_can_lines_preserve_id_as_metadata_and_payload_as_raw(self):
        result = parse_can(b"3.25\trx\tcan0\t0x123#DEADBEEF\n")
        self.assertEqual(result.format, "can-lines")
        message = result.messages[0]
        self.assertEqual(message.raw, bytes.fromhex("deadbeef"))
        self.assertEqual(dict(message.metadata), {"can_id": 0x123})
        self.assertEqual(
            parse_jsonl(result.to_jsonl().encode("utf-8")).messages[0].metadata,
            (("can_id", 0x123),),
        )
        with self.assertRaises(FormatError):
            parse_can(b"3.25\trx\tcan0\t123#ABC\n")
        with self.assertRaises(FormatError):
            parse_can(b"3.25\trx\tcan0\t20000000#00\n")
        with self.assertRaises(InputLimitError):
            parse_can(b"3.25\trx\tcan0\t123#" + b"00" * 65 + b"\n")

    def test_public_dataclasses_reject_unbounded_or_guessed_values(self):
        with self.assertRaises(ValueError):
            RawMessage(0, 0, "rx", b"", "source", boundary="guessed")
        with self.assertRaises(ValueError):
            NormalizedMessageCollection("jsonl", (RawMessage(1, 0, "rx", b"", "source"),))


if __name__ == "__main__":
    unittest.main()
