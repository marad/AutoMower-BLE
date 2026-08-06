import binascii
from automower_ble.helpers import crc
from enum import IntEnum
import asyncio
import logging
import json
from dataclasses import dataclass
from importlib.resources import files
from bleak.backends.characteristic import BleakGATTCharacteristic
from bleak_retry_connector import establish_connection, BleakClientWithServiceCache
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from bleak import BleakClient

logger = logging.getLogger(__name__)

# --- LOCAL PATCH (homelab, 2026-08-02) --------------------------------------
# This copy shadows the packaged automower-ble 0.2.9 through /config/deps.
# Two changes, both marked "LOCAL PATCH" below:
#   1. _read_data resynchronises on the 02 fd frame delimiter instead of
#      trusting data[2] as a length no matter what arrived.
#   2. validate_response dumps the raw frame when it rejects one.
#   3. response matching ignores delayed frames, including the unlinked
#      handshake response that can arrive while the PIN exchange is pending.
#   4. incomplete/invalid frames stay in the receive stream until their declared
#      length and trailer are present; a following delimiter is never consumed
#      as a missing tail.
#   5. notifications carry a session and arrival sequence so a response already
#      buffered before a new request cannot masquerade as its response.
# To disable: rename the automower_ble directory under /config/deps and
# restart Core. The packaged version in the image is untouched.
logger.warning(
    "automower_ble LOCAL PATCH v8 active: framing + response matching + "
    "arrival generations + complete-frame validation + safe connect parsing + "
    "schedule diagnostics"
)
# ----------------------------------------------------------------------------


def _has_valid_frame_boundary(frame: bytearray) -> bool:
    """Return whether ``frame`` has the declared length and trailer."""
    if len(frame) < 4 or frame[2] + 4 != len(frame):
        return False
    return frame[-1] == 0x03 and frame[-2] == crc(frame, 1, len(frame) - 3)


@dataclass(slots=True)
class _QueuedNotification:
    session: int
    sequence: int
    data: bytearray


class ModeOfOperation(IntEnum):
    # ProtocolTypes$IMowerAppMowerMode, used in modeOfOperation: 4586, 1
    # Comments from: https://developer.husqvarnagroup.cloud/apis/Automower+Connect+API?tab=status%20description%20and%20error%20codes#user-content-mode
    AUTO = 0
    MANUAL = 1
    HOME = 2  # Mower goes home and parks forever. Week schedule is not used. Cannot be overridden with forced mowing.
    DEMO = 3  # Same as main area, but shorter times. No blade operation
    POI = 4


class MowerState(IntEnum):
    # ProtocolTypes$IMowerAppState, used in mowerState: 4586, 2
    # Comments from: https://developer.husqvarnagroup.cloud/apis/Automower+Connect+API?tab=status%20description%20and%20error%20codes#user-content-state
    OFF = 0  # Mower is turned off.
    WAIT_FOR_SAFETYPIN = 1
    STOPPED = 2  # Mower is stopped requires manual action.
    FATAL_ERROR = 3
    PENDING_START = 4
    PAUSED = 5  # Mower has been paused by user.
    IN_OPERATION = 6  # See value in activity for status.
    RESTRICTED = (
        7  # Mower can currently not mow due to week calender, or override park.
    )
    ERROR = 8  # An error has occurred. Check errorCode. Mower requires manual action.


class MowerActivity(IntEnum):
    # ProtocolTypes$IMowerAppActivity, used in mowerActivity: 4586, 3
    # Comments from: https://developer.husqvarnagroup.cloud/apis/Automower+Connect+API?tab=status%20description%20and%20error%20codes#user-content-activity
    NONE = 0
    CHARGING = 1  # Mower is charging in station due to low battery.
    GOING_OUT = 2
    MOWING = 3  # Mower is mowing lawn. If in demo mode the blades are not in operation.
    GOING_HOME = 4  # Mower is going home to the charging station.
    PARKED = 5
    STOPPED_IN_GARDEN = 6  # Mower has stopped. Needs manual action to resume


class OverrideAction(IntEnum):
    NONE = 0
    FORCEDPARK = 1
    FORCEDMOW = 2


class ResponseResult(IntEnum):
    OK = 0
    UNKNOWN_ERROR = 1
    INVALID_VALUE = 2
    OUT_OF_RANGE = 3
    NOT_AVAILABLE = 4
    NOT_ALLOWED = 5
    INVALID_GROUP = 6
    INVALID_ID = 7
    DEVICE_BUSY = 8
    INVALID_PIN = 9
    MOWER_BLOCKED = 10


class InvalidResponseError(ValueError):
    """The mower sent a frame that is not a linked command response."""


class TaskInformation:
    def __init__(
        self,
        next_start_time,
        duration_in_seconds,
        on_monday,
        on_tuesday,
        on_wednesday,
        on_thursday,
        on_friday,
        on_saturday,
        on_sunday,
    ):
        self.next_start_time = next_start_time
        self.duration_in_seconds = duration_in_seconds
        self.on_monday = on_monday
        self.on_tuesday = on_tuesday
        self.on_wednesday = on_wednesday
        self.on_thursday = on_thursday
        self.on_friday = on_friday
        self.on_saturday = on_saturday
        self.on_sunday = on_sunday


class Command:
    def __init__(self, channel_id: int, parameter: dict):
        self.channel_id = channel_id

        self.major = parameter["major"]
        self.minor = parameter["minor"]

        self.request_data_type = parameter.get("requestType")

        if "responseType" not in parameter:
            parameter["responseType"] = "no_response"

        if not isinstance(parameter["responseType"], dict):  # Always wrap in list
            self.response_data_type = {"response": parameter["responseType"]}
        else:
            self.response_data_type = parameter["responseType"]
        self.request_data = bytearray()

    def generate_request(self, **kwargs) -> bytearray:
        self.request_data = bytearray(18)
        self.request_data[0] = 0x02  # Hard coded value (start of packet)
        self.request_data[1] = 0xFD  # 0xFD = LINKED_PACKET_TYPE
        self.request_data[2] = 0x00  # Length, low byte, updated later
        self.request_data[3] = 0x00  # Length, high byte, updated later

        # ChannelID
        self.request_data[4:8] = self.channel_id.to_bytes(4, byteorder="little")

        self.request_data[8] = 0x01  # is_linked (usually 0x01)

        self.request_data[9] = 0x00  # CRC, Updated later
        self.request_data[10] = (
            0x00  # Packet type (0x00 = request, 0x01 = response, 0x02 = event)
        )
        self.request_data[11] = 0xAF  # Hard coded value

        major_bytes = self.major.to_bytes(2, byteorder="little")

        self.request_data[12] = major_bytes[0]  # low byte of 'module'
        self.request_data[13] = major_bytes[1]  # high byte of 'module'
        self.request_data[14] = self.minor  # low byte of 'command'
        self.request_data[15] = 0x00  # high byte of 'command'

        # Byte 16 represents length of request data type
        request_length = 0
        request_data = bytearray()
        if self.request_data_type is not None:
            for request_name, request_type in self.request_data_type.items():
                if request_name not in kwargs:
                    raise ValueError(
                        "Missing request parameter: "
                        + request_name
                        + " for command ("
                        + str(self.major)
                        + ", "
                        + str(self.minor)
                        + ")"
                    )

                if request_type == "uint32":
                    request_length += 4
                    request_data += kwargs[request_name].to_bytes(4, byteorder="little")
                elif request_type == "uint16":
                    request_length += 2
                    request_data += kwargs[request_name].to_bytes(2, byteorder="little")
                elif request_type == "uint8":
                    request_length += 1
                    request_data += kwargs[request_name].to_bytes(1, byteorder="little")
                else:
                    raise ValueError("Unknown request type: " + request_type)
        self.request_data[16] = request_length

        self.request_data[17] = 0x00  # high byte of request_length
        if request_length > 0:
            self.request_data += request_data

        self.request_data[2] = len(self.request_data) - 2  # Length

        self.request_data[9] = crc(self.request_data, 1, 8)  # CRC

        # Two last bytes are crc and 0x03
        self.request_data.append(crc(self.request_data, 1, len(self.request_data) - 1))
        self.request_data.append(0x03)  # Hard coded value

        return self.request_data

    def parse_response(self, response_data: bytearray) -> dict[str, int | str] | None:
        response_length = response_data[17]
        data = response_data[19 : 19 + response_length]
        response: dict[str, int | str] = {}
        dpos = 0  # data position
        for name, dtype in self.response_data_type.items():
            if dtype == "no_response":
                return None
            if (dtype == "tUnixTime") or (dtype == "uint32"):
                response[name] = int.from_bytes(
                    data[dpos : dpos + 4], byteorder="little"
                )
                dpos += 4
            elif dtype == "uint16":
                response[name] = int.from_bytes(
                    data[dpos : dpos + 2], byteorder="little"
                )
                dpos += 2
            elif (dtype == "uint8") or (dtype == "bool"):
                response[name] = data[dpos]
                dpos += 1
            elif dtype == "ascii":
                if len(self.response_data_type) != 1:
                    raise ValueError(
                        "ASCII response type can currently only be used when there is only one response type"
                    )
                response[name] = data.decode("ascii").rstrip(
                    "\x00"
                )  # Remove trailing null bytes
                dpos += len(data)
            else:
                raise ValueError("Unknown data type: " + dtype)
        if dpos != len(data):
            raise ValueError(f"Data length mismatch. Read {dpos} bytes of {len(data)}")
        return response

    def is_response_to_this_command(self, response_data: bytearray) -> bool:
        """LOCAL PATCH v7: does this complete frame answer *this* request?

        Deliberately narrower than validate_command_response: it checks the
        linked-frame envelope and command identity, but not the result byte, so
        a genuine error response to our own request still counts as ours and is
        not retried away.
        """
        if (
            len(response_data) < 17
            or response_data[:2] != b"\x02\xfd"
            or not _has_valid_frame_boundary(response_data)
        ):
            return False
        if response_data[3] != 0x00:
            return False
        if response_data[4:8] != self.channel_id.to_bytes(4, byteorder="little"):
            return False
        if response_data[8] != 0x01 or response_data[10] != 0x01:
            return False
        if response_data[11] != 0xAF:
            return False
        major_bytes = self.major.to_bytes(4, byteorder="little")
        return (
            response_data[12] == major_bytes[0]
            and response_data[13] == major_bytes[1]
            and response_data[14] == self.minor
        )

    def validate_command_response(self, response_data: bytearray) -> bool:
        if response_data[0] != 0x02:
            return False

        if response_data[1] != 0xFD:
            return False

        if response_data[3] != 0x00:  # high byte of length
            return False

        if response_data[4:8] != self.channel_id.to_bytes(4, byteorder="little"):
            return False

        if response_data[8] != 0x01:
            # This is a valid config, but we don't support it
            # return m1656b(decodeState, c10786f);
            return False

        if response_data[9] != crc(response_data, 1, 8):
            return False

        if response_data[10] != 0x01:  # packet type is not 0x01 = response
            return False

        if response_data[11] != 0xAF:
            return False

        major_bytes = self.major.to_bytes(4, byteorder="little")
        if response_data[12] != major_bytes[0]:
            return False
        if response_data[13] != major_bytes[1]:
            return False
        if response_data[14] != self.minor:
            return False

        if response_data[15] != 0x00:  # high byte of 'command' (self.minor)
            return False

        if (
            response_data[16] != 0x00
        ):  # result: OK(0), UNKNOWN_ERROR(1), INVALID_VALUE(2), OUT_OF_RANGE(3), NOT_AVAILABLE(4), NOT_ALLOWED(5), INVALID_GROUP(6), INVALID_ID(7), DEVICE_BUSY(8), INVALID_PIN(9), MOWER_BLOCKED(10);
            logger.warning("Non zero response result: %d", response_data[16])
            return False

        return True


class BLEClient:
    def __init__(self, channel_id: int, address, pin=None):
        self.channel_id = channel_id
        self.address = address
        self.pin = pin
        self.MTU_SIZE = 20

        self.lock = asyncio.Lock()
        self.queue: asyncio.Queue[_QueuedNotification | None] = asyncio.Queue()

        # Every notification gets a monotonically increasing arrival sequence.
        # A request records the current value before writing; complete frames
        # whose last byte predates that watermark are stale leftovers from an
        # earlier request and are not allowed to satisfy the new one. A frame
        # that completes while the write is in progress remains eligible.
        self._session = 0
        self._notification_sequence = 0

        # LOCAL PATCH v3: bytes read past the end of the previous frame. Upstream
        # throws these away, which destroys the head of the next frame and makes
        # the desync permanent.
        self._rx = bytearray()
        self._rx_sequences: list[int] = []

        self.client: BleakClient | None = None
        self.protocol = None

    async def get_protocol(self):
        if self.protocol is None:

            def read_protocol_file():
                with files("automower_ble").joinpath("protocol.json").open("r") as f:
                    return json.load(f)

            self.protocol = await asyncio.get_running_loop().run_in_executor(
                None, read_protocol_file
            )
        return self.protocol

    def _make_notification(self, data, session=None):
        """Stamp a notification at the point it enters the receive queue."""
        self._notification_sequence += 1
        return _QueuedNotification(
            self._session if session is None else session,
            self._notification_sequence,
            bytearray(data),
        )

    def _queue_notification(self, data, session=None):
        """Test/helper hook matching the production notification callback."""
        self.queue.put_nowait(self._make_notification(data, session=session))

    def _reset_receive_state(self, clear_queue=False):
        self._rx = bytearray()
        self._rx_sequences = []
        if clear_queue:
            while True:
                try:
                    self.queue.get_nowait()
                except asyncio.QueueEmpty:
                    break

    async def _get_notification(self, timeout=10):
        """Return the next notification for the active session."""
        deadline = asyncio.get_running_loop().time() + timeout
        while True:
            remaining = max(0, deadline - asyncio.get_running_loop().time())
            try:
                item = await asyncio.wait_for(self.queue.get(), timeout=remaining)
            except TimeoutError:
                logger.error(
                    "Unable to get response from device: '%s'", self.address
                )
                return None

            if item is None:
                return None

            # Keep compatibility with raw bytearray queue entries used by older
            # callers; production and updated tests use stamped notifications.
            if not isinstance(item, _QueuedNotification):
                item = self._make_notification(item)

            if item.session != self._session:
                logger.debug(
                    "PATCH: ignoring notification from old session %d (current %d)",
                    item.session,
                    self._session,
                )
                continue
            return item

    async def _get_response(self, timeout=10):
        try:
            notification = await self._get_notification(timeout=timeout)

        except TimeoutError:
            logger.error("Unable to get response from device: '%s'", self.address)
            return None

        return None if notification is None else notification.data

    async def _write_data(self, data):
        logger.info("Writing: %s", str(binascii.hexlify(data)))

        chunk_size = self.MTU_SIZE - 3
        for chunk in (
            data[i : i + chunk_size] for i in range(0, len(data), chunk_size)
        ):
            await self.client.write_gatt_char(self.write_char, chunk, response=False)

        logger.debug("Finished writing")

    FRAME_DELIMITER = b"\x02\xfd"
    MAX_RESYNC_BYTES = 512
    MAX_FRAME_LENGTH = 259

    async def _fill(self, data, sequences, timeout=10):
        """Append one stamped notification, or None if nothing arrives."""
        notification = await self._get_notification(timeout=timeout)
        if notification is None:
            return None
        data.extend(notification.data)
        sequences.extend([notification.sequence] * len(notification.data))
        return data, sequences

    async def _read_data(self, timeout=10, min_sequence=None):
        # --- LOCAL PATCH v8: a complete-frame receive layer -------------------
        # Notifications are fragments, not frames.  Keep a persistent byte
        # buffer, wait for the declared length, and validate the trailer before
        # returning anything to the command matcher.  If a previous cycle lost
        # a tail, the next 02 fd delimiter is preserved for resynchronisation;
        # it is never consumed as the missing CRC/terminator.
        deadline = asyncio.get_running_loop().time() + timeout

        def remaining():
            return max(0, deadline - asyncio.get_running_loop().time())

        data = bytearray(self._rx)
        sequences = list(self._rx_sequences)
        if data and len(sequences) != len(data):
            # A raw _rx value can only come from an older caller/test. Treat it
            # as pre-existing data so it cannot satisfy a newly started request.
            sequences = [0] * len(data)
        self._reset_receive_state()

        if not data:
            filled = await self._fill(data, sequences, timeout=remaining())
            if filled is None:
                return None
            data, sequences = filled

        dropped = 0
        while True:
            # 1. Find a frame delimiter.  Bytes before it are an orphaned tail
            # or a fragment from an invalid frame and can be discarded.
            while (offset := data.find(self.FRAME_DELIMITER)) == -1:
                if len(data) > self.MAX_RESYNC_BYTES:
                    logger.error(
                        "PATCH: no frame delimiter in %d bytes, dropping: '%s'",
                        len(data),
                        binascii.hexlify(data).decode(),
                    )
                    return None
                filled = await self._fill(data, sequences, timeout=remaining())
                if filled is None:
                    return None
                data, sequences = filled
            if offset:
                dropped += offset
                data = data[offset:]
                sequences = sequences[offset:]

            # 2. Need four bytes to read the declared length.
            while len(data) < 4:
                filled = await self._fill(data, sequences, timeout=remaining())
                if filled is None:
                    return None
                data, sequences = filled

            # A real frame has a zero high length byte.  If a delimiter occurs
            # inside a payload, step over it and look for the next candidate.
            if data[3] != 0x00:
                logger.warning(
                    "PATCH: false frame head (byte3=0x%02x), stepping over it",
                    data[3],
                )
                dropped += 2
                data = data[2:]
                sequences = sequences[2:]
                continue

            length = data[2] + 4
            if not 4 <= length <= self.MAX_FRAME_LENGTH:
                logger.warning(
                    "PATCH: invalid frame length %d from '%s'",
                    length,
                    binascii.hexlify(data[:4]).decode(),
                )
                dropped += 2
                data = data[2:]
                sequences = sequences[2:]
                continue

            logger.debug("Waiting for %d bytes", length)
            while len(data) < length:
                filled = await self._fill(data, sequences, timeout=remaining())
                if filled is None:
                    logger.error(
                        "Unable to get full response from device: '%s'", self.address
                    )
                    logger.error(
                        "Expecting %d bytes, only have %d", length, len(data or b"")
                    )
                    return None
                data, sequences = filled

            frame = data[:length]
            if not _has_valid_frame_boundary(frame):
                if frame[length - 1] != 0x03:
                    logger.warning(
                        "PATCH: frame does not end in 0x03: '%s'",
                        binascii.hexlify(frame).decode(),
                    )
                else:
                    expected = crc(frame, 1, length - 3)
                    logger.warning(
                        "PATCH: trailing CRC mismatch, got 0x%02x expected 0x%02x: '%s'",
                        frame[length - 2],
                        expected,
                        binascii.hexlify(frame).decode(),
                    )

                # Prefer the next delimiter already present in the accumulated
                # bytes.  This is the common 20-byte head + next 02 fd case and
                # preserves the next frame instead of consuming its first bytes.
                next_offset = data.find(self.FRAME_DELIMITER, 2)
                if next_offset >= 0:
                    dropped += next_offset
                    data = data[next_offset:]
                    sequences = sequences[next_offset:]
                    if dropped > self.MAX_RESYNC_BYTES:
                        logger.error(
                            "PATCH: exceeded resync limit while rejecting frames"
                        )
                        return None
                    continue

                # No next delimiter is available yet.  Retain a possible first
                # delimiter byte and wait for another notification.
                dropped += max(0, len(data) - 1)
                data = data[-1:] if data[-1:] == self.FRAME_DELIMITER[:1] else bytearray()
                sequences = sequences[-1:] if data else []
                continue

            # A response may start arriving while the request is still being
            # written.  Reject only a frame whose *last* byte was already
            # queued before the request watermark; a frame completed after the
            # write may legitimately have its first fragment before it.
            frame_last_sequence = sequences[length - 1]
            if min_sequence is not None and frame_last_sequence < min_sequence:
                logger.warning(
                    "PATCH: discarding stale frame from before request "
                    "(last notification %d < %d): '%s'",
                    frame_last_sequence,
                    min_sequence,
                    binascii.hexlify(frame).decode(),
                )
                data = data[length:]
                sequences = sequences[length:]
                continue

            if dropped:
                logger.warning("PATCH: discarded %d byte(s) before the frame", dropped)

            # Keep every byte after this complete frame for the next read.  It
            # may already contain one or more complete notifications.
            self._rx = bytearray(data[length:])
            self._rx_sequences = list(sequences[length:])
            if self._rx:
                logger.warning(
                    "PATCH: kept %d surplus byte(s) for the next read: '%s'",
                    len(self._rx),
                    binascii.hexlify(self._rx).decode(),
                )

            logger.info("Final response: %s", str(binascii.hexlify(frame)))
            return frame

    async def _request_response(self, request_data, is_ours=None, timeout=10):
        async with self.lock:
            try:
                # Record the receive watermark before writing.  Notifications
                # already stamped at or below it belong to an earlier request;
                # a response generated after this write gets a higher sequence.
                request_sequence = self._notification_sequence

                # Do not flush the queue or _rx here.  A notification may be the
                # tail of a frame that started during the previous request.  The
                # framing layer will finish it and the response matcher will
                # discard it if it belongs to an earlier command.
                await self._write_data(request_data)

                # LOCAL PATCH v8: a frame arriving now may answer an earlier
                # request. Keep reading until the expected response arrives or
                # the overall deadline expires; a fixed count is unsafe because
                # the mower can repeat a delayed response several times.
                deadline = asyncio.get_running_loop().time() + timeout
                skipped = 0
                while True:
                    remaining = deadline - asyncio.get_running_loop().time()
                    if remaining <= 0:
                        logger.error(
                            "PATCH: no matching response after %d foreign frames",
                            skipped,
                        )
                        return None

                    response_data = await self._read_data(
                        timeout=remaining,
                        min_sequence=request_sequence + 1,
                    )
                    if response_data is None:
                        logger.error(
                            "Unable to communicate with device: '%s'", self.address
                        )
                        if self.is_connected():
                            await self.disconnect()
                        return None
                    if is_ours is None or is_ours(response_data):
                        break
                    skipped += 1
                    logger.warning(
                        "PATCH: discarding a response to an earlier request "
                        "(%d): %s",
                        skipped,
                        binascii.hexlify(response_data).decode(),
                    )

            except asyncio.exceptions.CancelledError:
                logger.debug("Received CancelledError")
                if self.is_connected():
                    await self.disconnect()
                return None

        return response_data

    async def connect(self, device) -> ResponseResult:
        """
        Connect to a device and setup the channel

        Returns a ResponseResult
        """
        logger.info("starting scan...")

        # A new GATT session cannot complete fragments from the old session.
        # Clear its sentinel/queued bytes here, once per reconnect, rather than
        # flushing a potentially live frame before every request.
        self._session += 1
        session = self._session
        self._reset_receive_state(clear_queue=True)

        if device is None:
            logger.error("could not find device with address '%s'", self.address)
            return ResponseResult.UNKNOWN_ERROR

        logger.info("connecting to device...")
        self.client = await establish_connection(
            BleakClientWithServiceCache,
            device,
            device.name or "Unknown Device",
        )
        logger.info("connected")

        logger.info("pairing device...")
        try:
            await self.client.pair()
            logger.info("paired")
        except Exception as err:
            logger.debug("Pairing not completed, continuing anyway: %s", err)

        # This is not safe, _mtu_size is not defined in BaseBleakClient but may
        # be defined in subclasses.
        self.client._backend._mtu_size = self.MTU_SIZE  # type: ignore[attr-defined]

        for service in self.client.services:
            logger.info("[Service] %s", service)

            for char in service.characteristics:
                if (
                    "read" in char.properties
                    and char.uuid != "98bd0003-0b0e-421a-84e5-ddbf75dc6de4"
                ):
                    try:
                        value = await self.client.read_gatt_char(char.uuid)
                        logger.debug(
                            "  [Characteristic] %s (%s), Value: %r",
                            char,
                            ",".join(char.properties),
                            value,
                        )
                    except Exception as e:
                        logger.error(
                            "  [Characteristic] %s (%s), Error: %s",
                            char,
                            ",".join(char.properties),
                            e,
                        )
                else:
                    logger.debug(
                        "  [Characteristic] %s (%s)", char, ",".join(char.properties)
                    )
                if char.uuid == "98bd0002-0b0e-421a-84e5-ddbf75dc6de4":
                    self.write_char = char

                if char.uuid == "98bd0003-0b0e-421a-84e5-ddbf75dc6de4":
                    self.read_char = char

        async def notification_handler(
            characteristic: BleakGATTCharacteristic, data: bytearray
        ):
            logger.info("Received: %s", str(binascii.hexlify(data)))
            await self.queue.put(self._make_notification(data, session=session))

        try:
            await self.client.start_notify(self.read_char, notification_handler)
        except Exception:
            await self.client.disconnect()
            raise

        await asyncio.sleep(5.0)

        request = self.generate_request_setup_channel_id()
        response = await self._request_response(request)
        if response is None:
            return ResponseResult.UNKNOWN_ERROR

        request = self.generate_request_handshake()
        response = await self._request_response(request)
        if response is None:
            return ResponseResult.UNKNOWN_ERROR

        if self.pin is not None:
            command = Command(
                self.channel_id, (await self.get_protocol())["EnterOperatorPin"]
            )
            request = command.generate_request(code=self.pin)
            response = await self._request_response(
                request,
                is_ours=command.is_response_to_this_command,
            )
            if response is None:
                return ResponseResult.UNKNOWN_ERROR
            try:
                result = self.get_response_result(response)
            except InvalidResponseError as err:
                logger.warning("Invalid EnterOperatorPin response: %s", err)
                return ResponseResult.UNKNOWN_ERROR
            # If the result is UNKNOWN_ERROR, assume the pin was invalid
            return (
                ResponseResult.INVALID_PIN
                if result == ResponseResult.UNKNOWN_ERROR
                else result
            )

        return ResponseResult.OK

    def is_connected(self) -> bool:
        return bool(self.client and self.client.is_connected)

    async def probe_gatts(self, device):
        logger.info("connecting to device...")
        client = await establish_connection(
            BleakClientWithServiceCache,
            device,
            device.name or "Unknown Device",
            max_attempts=3,  # Will retry up to 3 times with backoff
        )
        logger.info("connected")

        manufacture = None
        model = None
        device_type = None

        for service in client.services:
            logger.debug("[Service] %s", service)

            if service.uuid == "98bd0001-0b0e-421a-84e5-ddbf75dc6de4":
                manufacture = service.description

            for char in service.characteristics:
                if "read" in char.properties:
                    try:
                        value = await client.read_gatt_char(char.uuid)
                        logger.debug(
                            "  [Characteristic] %s (%s), Value: %r",
                            char,
                            ",".join(char.properties),
                            value,
                        )
                        if char.uuid == "00002a00-0000-1000-8000-00805f9b34fb":
                            model = value.decode()
                        if char.uuid == "98bd0004-0b0e-421a-84e5-ddbf75dc6de4":
                            device_type = value.rstrip(b"\x00").decode()
                    except Exception as e:
                        logger.error(
                            "  [Characteristic] %s (%s), Error: %s",
                            char,
                            ",".join(char.properties),
                            e,
                        )
                else:
                    logger.debug(
                        "  [Characteristic] %s (%s)", char, ",".join(char.properties)
                    )

        await client.disconnect()

        return (manufacture, device_type, model)

    async def disconnect(self):
        """
        Disconnect from the mower, this should be called after every
        `connect()` before the Python script exits
        """

        logger.info("disconnecting...")
        await self.client.disconnect()
        logger.info("disconnected")

        # Nothing from this GATT session may be joined to a future one.  The
        # sentinel still wakes any reader that is waiting for a notification.
        self._session += 1
        self._reset_receive_state(clear_queue=True)
        await self.queue.put(None)

    def generate_request_setup_channel_id(self) -> bytearray:
        """
        Setup the channelID with an Automower, this is the first
        command that should be sent
        """
        data = bytearray.fromhex("02fd160000000000002e1400000000000000004d61696e00")

        # New ChannelID
        data[11:15] = self.channel_id.to_bytes(4, byteorder="little")

        # CRC and end byte
        data[9] = crc(data, 1, 8)
        data.append(crc(data, 1, len(data) - 1))
        data.append(0x03)

        return data

    def generate_request_handshake(self) -> bytearray:
        """
        Generate a request handshake. This should be called after
        the channel id is set up but before other commands
        """
        data = bytearray.fromhex("02fd0a000000000000d00801")

        data[4:8] = self.channel_id.to_bytes(4, byteorder="little")

        # CRCs and end byte
        data[9] = crc(data, 1, 8)
        data.append(crc(data, 1, len(data) - 1))
        data.append(0x03)

        return data

    def validate_response(self, response_data: bytearray) -> bool:
        # --- LOCAL PATCH: dump the raw frame whenever validation rejects it ---
        ok = self._validate_response_checks(response_data)
        if not ok:
            logger.warning(
                "PATCH: validation failed, len=%d channel_id=%s frame='%s'",
                len(response_data),
                hex(self.channel_id),
                str(binascii.hexlify(response_data)),
            )
        return ok

    def _validate_response_checks(
        self, response_data: bytearray, require_ok: bool = True
    ) -> bool:
        if len(response_data) < 17:
            return False

        if not _has_valid_frame_boundary(response_data):
            return False

        if response_data[0] != 0x02:
            return False

        if response_data[1] != 0xFD:
            return False

        if response_data[3] != 0x00:  # high byte of length
            return False

        if response_data[4:8] != self.channel_id.to_bytes(4, byteorder="little"):
            return False

        if response_data[8] != 0x01:
            # This is a valid config, but we don't support it
            # return m1656b(decodeState, c10786f);
            return False

        if response_data[9] != crc(response_data, 1, 8):
            return False

        if response_data[10] != 0x01:  # packet type is not 0x01 = response
            return False

        if response_data[11] != 0xAF:
            return False

        if require_ok and response_data[16] != 0x00:
            logger.warning("Non zero response result: %d", response_data[16])
            return False

        return True

    def get_response_result(self, response_data: bytearray) -> ResponseResult:
        # A non-zero result is a valid response (for example INVALID_PIN), so
        # validate the frame structure separately from the result value. The
        # old implementation logged a failed validation and then indexed byte
        # 16 unconditionally, which crashed on the 15-byte unlinked handshake
        # response.
        if not self._validate_response_checks(response_data, require_ok=False):
            logger.warning("Response failed validation")
            raise InvalidResponseError(
                f"invalid linked response ({len(response_data)} bytes): "
                f"{binascii.hexlify(response_data).decode()}"
            )

        try:
            return ResponseResult(response_data[16])
        except (IndexError, ValueError) as err:
            raise InvalidResponseError(
                f"invalid response result in frame: "
                f"{binascii.hexlify(response_data).decode()}"
            ) from err
