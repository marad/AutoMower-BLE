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
LINKED_RESPONSE_WITH_DELAYED_TAIL = bytearray.fromhex(
    # The 20-byte response head was observed followed by the next frame's
    # delimiter before its two-byte CRC/terminator tail arrived.
    "02fd120088f0ea20016c01afea1103000001000502fd"
)


def linked_response(command: Command, result: int = 0) -> bytearray:
    # A no-payload linked response is 19 bytes: 15 bytes after the envelope,
    # plus the two-byte CRC/terminator trailer.
    frame = bytearray.fromhex("02fd0f00")
    frame.extend(CHANNEL_ID.to_bytes(4, byteorder="little"))
    frame.extend(b"\x01\x00\x01\xaf")
    frame.extend(command.major.to_bytes(2, byteorder="little"))
    frame.extend((command.minor, 0, result))
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

    def test_linked_response_head_survives_delayed_tail(self):
        client = BLEClient(CHANNEL_ID, "00:00:00:00:00:00")

        self.assertEqual(
            client.get_response_result(LINKED_RESPONSE_WITH_DELAYED_TAIL),
            ResponseResult.OK,
        )

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
