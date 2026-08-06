import asyncio
import json
import unittest
from importlib.resources import files
from types import SimpleNamespace
from unittest.mock import AsyncMock

from automower_ble.helpers import crc
from automower_ble.protocol import (
    BLEClient,
    Command,
    InvalidResponseError,
    ResponseResult,
)


CHANNEL_ID = 0x20EAF088
UNLINKED_HANDSHAKE_RESPONSE = bytearray.fromhex(
    "02fd0b0088f0ea2000050901011403"
)
MALFORMED_RESPONSE_WITH_NEXT_DELIMITER = bytearray.fromhex(
    # The 20-byte response head was observed followed by the next frame's
    # delimiter instead of its two-byte CRC/terminator tail.
    "02fd120088f0ea20016c01afea1103000001000502fd"
)


def linked_response(
    command: Command, result: int = 0, payload: bytes = b""
) -> bytearray:
    frame = bytearray.fromhex("02fd0000")
    frame.extend(CHANNEL_ID.to_bytes(4, byteorder="little"))
    frame.extend(b"\x01\x00\x01\xaf")
    frame.extend(command.major.to_bytes(2, byteorder="little"))
    frame.extend((command.minor, 0, result))
    if payload:
        frame.extend((len(payload), 0))
        frame.extend(payload)
    frame[2] = len(frame) - 2
    frame[9] = crc(frame, 1, 8)
    frame.append(crc(frame, 1, len(frame) - 1))
    frame.append(0x03)
    return frame


class TestProtocolResponses(unittest.IsolatedAsyncioTestCase):
    @classmethod
    def setUpClass(cls):
        with files("automower_ble").joinpath("protocol.json").open("r") as f:
            cls.protocol = json.load(f)

    def test_unlinked_handshake_frame_is_typed_error(self):
        client = BLEClient(CHANNEL_ID, "00:00:00:00:00:00")

        with self.assertRaises(InvalidResponseError):
            client.get_response_result(UNLINKED_HANDSHAKE_RESPONSE)

    def test_nonzero_linked_result_is_preserved(self):
        command = Command(CHANNEL_ID, self.protocol["EnterOperatorPin"])
        client_result = BLEClient(CHANNEL_ID, "00:00:00:00:00:00").get_response_result(
            linked_response(command, ResponseResult.INVALID_PIN.value)
        )
        self.assertEqual(
            client_result,
            ResponseResult.INVALID_PIN,
        )
        self.assertIsInstance(client_result, ResponseResult)

    def test_malformed_frame_is_rejected(self):
        client = BLEClient(CHANNEL_ID, "00:00:00:00:00:00")

        with self.assertRaises(InvalidResponseError):
            client.get_response_result(MALFORMED_RESPONSE_WITH_NEXT_DELIMITER)

    async def test_waits_for_declared_tail(self):
        command = Command(CHANNEL_ID, self.protocol["GetBatteryLevel"])
        expected = linked_response(command, payload=b"\x05")
        client = BLEClient(CHANNEL_ID, "00:00:00:00:00:00")
        client.queue.put_nowait(expected[:20])
        client.queue.put_nowait(expected[20:])

        self.assertEqual(await client._read_data(timeout=1), expected)
        self.assertEqual(client._rx, bytearray())

    async def test_invalid_frame_preserves_next_delimiter(self):
        command = Command(CHANNEL_ID, self.protocol["GetBatteryLevel"])
        expected = linked_response(command, payload=b"\x06")
        client = BLEClient(CHANNEL_ID, "00:00:00:00:00:00")
        client.queue.put_nowait(expected[:20])
        client.queue.put_nowait(expected)

        # The first frame is missing its two-byte tail.  The parser must not
        # consume the next frame's 02 fd as that tail.
        self.assertEqual(await client._read_data(timeout=1), expected)
        self.assertEqual(client._rx, bytearray())

    async def test_surplus_complete_frame_is_retained(self):
        command = Command(CHANNEL_ID, self.protocol["GetBatteryLevel"])
        first = linked_response(command, payload=b"\x05")
        second = linked_response(command, payload=b"\x06")
        client = BLEClient(CHANNEL_ID, "00:00:00:00:00:00")
        client.queue.put_nowait(first + second)

        self.assertEqual(await client._read_data(timeout=1), first)
        self.assertEqual(await client._read_data(timeout=1), second)

    async def test_request_keeps_partial_frame_across_write(self):
        command = Command(CHANNEL_ID, self.protocol["EnterOperatorPin"])
        expected = linked_response(command)
        client = BLEClient(CHANNEL_ID, "00:00:00:00:00:00")
        client.client = SimpleNamespace(is_connected=True)
        client.disconnect = AsyncMock()
        client.queue.put_nowait(expected[:-2])

        async def write(_request):
            client.queue.put_nowait(expected[-2:])

        client._write_data = write

        response = await client._request_response(
            command.generate_request(code=7201),
            is_ours=command.is_response_to_this_command,
            timeout=1,
        )

        self.assertEqual(response, expected)
        client.disconnect.assert_not_awaited()

    async def test_disconnect_drops_incomplete_frame_before_next_session(self):
        command = Command(CHANNEL_ID, self.protocol["GetBatteryLevel"])
        expected = linked_response(command, payload=b"\x05")
        client = BLEClient(CHANNEL_ID, "00:00:00:00:00:00")

        # The link disappears after only a fragment.  The partial frame must
        # not be joined to bytes received after the next GATT connection.
        client.queue.put_nowait(expected[:20])
        client.queue.put_nowait(None)
        self.assertIsNone(await client._read_data(timeout=1))
        self.assertEqual(client._rx, bytearray())

        client.queue.put_nowait(expected)
        self.assertEqual(await client._read_data(timeout=1), expected)

    async def test_timeout_then_late_foreign_response_is_skipped(self):
        stale_command = Command(CHANNEL_ID, self.protocol["GetBatteryLevel"])
        current_command = Command(CHANNEL_ID, self.protocol["EnterOperatorPin"])
        stale = linked_response(stale_command, payload=b"\x05")
        expected = linked_response(current_command)
        client = BLEClient(CHANNEL_ID, "00:00:00:00:00:00")
        client.client = SimpleNamespace(is_connected=True)
        client.disconnect = AsyncMock()
        client._write_data = AsyncMock()

        # The first request times out.  A response to it arrives only after
        # that timeout, before the next request is issued.
        self.assertIsNone(
            await client._request_response(
                current_command.generate_request(code=7201),
                is_ours=current_command.is_response_to_this_command,
                timeout=0.01,
            )
        )
        client.disconnect.assert_awaited_once()

        client.queue.put_nowait(stale)
        client.queue.put_nowait(expected)
        response = await client._request_response(
            current_command.generate_request(code=7201),
            is_ours=current_command.is_response_to_this_command,
            timeout=1,
        )

        self.assertEqual(response, expected)
        self.assertEqual(client.get_response_result(response), ResponseResult.OK)

    async def test_pin_request_skips_delayed_handshake_response(self):
        command = Command(CHANNEL_ID, self.protocol["EnterOperatorPin"])
        expected = linked_response(command)
        client = BLEClient(CHANNEL_ID, "00:00:00:00:00:00")
        client.queue = asyncio.Queue()
        client._rx = bytearray()
        client.lock = asyncio.Lock()
        client.client = SimpleNamespace(is_connected=True)
        client.disconnect = AsyncMock()

        async def write(_request):
            client.queue.put_nowait(UNLINKED_HANDSHAKE_RESPONSE)
            client.queue.put_nowait(expected)

        client._write_data = write

        response = await client._request_response(
            command.generate_request(code=7201),
            is_ours=command.is_response_to_this_command,
            timeout=1,
        )

        self.assertEqual(response, expected)
        self.assertEqual(client.get_response_result(response), ResponseResult.OK)
        client.disconnect.assert_not_awaited()
