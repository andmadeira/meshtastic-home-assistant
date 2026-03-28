# SPDX-FileCopyrightText: 2024-2025 Pascal Brogle @broglep
# SPDX-FileCopyrightText: 2025 Hendrik @novag
#
# SPDX-License-Identifier: MIT

import asyncio
import struct
from collections.abc import AsyncGenerator, Awaitable, Callable
from contextlib import suppress
from typing import TYPE_CHECKING, Any

import bleak
from bleak import BleakScanner, BleakError
from bleak.args.bluez import BlueZStartNotifyArgs
from bleak.backends.characteristic import BleakGATTCharacteristic
from bleak.backends.client import BaseBleakClient
from bleak.backends.device import BLEDevice
from bleak.backends.service import BleakGATTService
from bleak.exc import BleakDBusError
from bleak_retry_connector import BleakClientWithServiceCache, establish_connection
from homeassistant.components.bluetooth import async_ble_device_from_address
from homeassistant.core import HomeAssistant

from google.protobuf import message
from ..protobuf import mesh_pb2  # noqa: TID252
from . import ClientApiConnection
from .errors import (
    ClientApiConnectionError,
    ClientApiNotConnectedError,
)

if TYPE_CHECKING:
    from bleak.backends.service import BleakGATTService


class BluetoothConnectionError(ClientApiConnectionError):
    pass


class BluetoothConnectionServiceNotFoundError(BluetoothConnectionError):
    def __init__(self) -> None:
        super().__init__("Bluetooth meshtastic service not found")


class BluetoothConnectionDeviceNotFoundError(BluetoothConnectionError):
    def __init__(self, ble_address: str) -> None:
        super().__init__(f"Bluetooth meshtastic device {ble_address} not found")


class BluetoothConnection(ClientApiConnection):
    BTM_SERVICE_UUID = "6ba1b218-15a8-461f-9fa8-5dcae273eafd"
    BTM_CHARACTERISTIC_FROM_RADIO_UUID = "2c55e69e-4993-11ed-b878-0242ac120002"
    BTM_CHARACTERISTIC_TO_RADIO_UUID = "f75c76d2-129e-4dad-a1dd-7866124401e7"
    BTM_CHARACTERISTIC_FROM_NUM_UUID = "ed9da18c-a800-4f66-a670-aa7547e34453"
    BTM_CHARACTERISTIC_LOG_UUID = "5a3d6e49-06e6-4423-9944-e9de8cdf9547"

    def __init__(
        self,
        hass: HomeAssistant,
        ble_address: str,
        ble_device: BLEDevice | None = None,
        bleak_client_backend: type[BaseBleakClient] | None = None,
        connect_timeout: float = 10.0,
    ) -> None:
        super().__init__()
        self._hass = hass
        self._ble_address = ble_address
        self._ble_device = ble_device
        self._bleak_client_backend = bleak_client_backend
        self._connect_timeout = connect_timeout

        self._bleak_client = None
        self._ble_meshtastic_service: BleakGATTService | None = None
        self._ble_from_radio: BleakGATTCharacteristic | None = None
        self._ble_to_radio: BleakGATTCharacteristic | None = None
        self._ble_from_num: BleakGATTCharacteristic | None = None
        self._ble_log: BleakGATTCharacteristic | None = None

        self._write_lock = asyncio.Lock()
        self._connect_lock = asyncio.Lock()
        self._last_packet_number = None
        self._force_read_event = asyncio.Event()
        self._notify_started = False
        self._notify_lock = asyncio.Lock()

    async def _connect(self) -> None:
        async with self._connect_lock:
            if self._bleak_client and self._bleak_client.is_connected:
                return

            device: BLEDevice | None = self._ble_device

            # 1) Preferir o BLEDevice já conhecido pelo Home Assistant
            if device is None:
                device = async_ble_device_from_address(
                    self._hass,
                    self._ble_address,
                    connectable=True,
                )

            # 2) Fallback para scan direto apenas se o HA não o tiver em cache
            if device is None:
                device = await BleakScanner.find_device_by_address(
                    self._ble_address,
                    timeout=self._connect_timeout,
                )

            if device is None:
                raise BluetoothConnectionDeviceNotFoundError(self._ble_address)

            self._ble_device = device

            self._bleak_client = await establish_connection(
                BleakClientWithServiceCache,
                device,
                device.name or self._ble_address,
                disconnected_callback=None,
                timeout=self._connect_timeout,
                max_attempts=3,
                pair=True,
                backend=self._bleak_client_backend,
            )

            services = self._bleak_client.services
            self._ble_meshtastic_service = services.get_service(self.BTM_SERVICE_UUID)

            if self._ble_meshtastic_service is None:
                raise BluetoothConnectionServiceNotFoundError()

            self._ble_from_radio = self._ble_meshtastic_service.get_characteristic(
                self.BTM_CHARACTERISTIC_FROM_RADIO_UUID
            )
            self._ble_to_radio = self._ble_meshtastic_service.get_characteristic(self.BTM_CHARACTERISTIC_TO_RADIO_UUID)
            self._ble_from_num = self._ble_meshtastic_service.get_characteristic(self.BTM_CHARACTERISTIC_FROM_NUM_UUID)
            self._ble_log = self._ble_meshtastic_service.get_characteristic(self.BTM_CHARACTERISTIC_LOG_UUID)

            if (
                self._ble_from_radio is None
                or self._ble_to_radio is None
                or self._ble_from_num is None
                or self._ble_log is None
            ):
                raise BluetoothConnectionServiceNotFoundError()

    async def _disconnect(self) -> None:
        if self._bleak_client is None:
            self._notify_started = False
            return

        try:
            await self._bleak_client.disconnect()
        except:  # noqa: E722
            self._logger.debug("Disconnecting failed", exc_info=True)
        finally:
            self._notify_started = False
            self._bleak_client = None
            self._ble_meshtastic_service = None
            self._ble_from_radio = None
            self._ble_to_radio = None
            self._ble_from_num = None
            self._ble_log = None

    @property
    def is_connected(self) -> bool:
        return self._bleak_client is not None and self._bleak_client.is_connected

    async def _handle_notify_wait(  # noqa: PLR0913
        self,
        packet_num_queue: asyncio.Queue,
        force_read_event: asyncio.Event,
        notify_timeout_duration: int,
        notify_timeout_count: int,
        max_notify_timeouts_before_restart: int,
        restart_notify_func: Callable[[], Awaitable[None]],
    ) -> tuple[bool, int]:
        """Wait for packet notification or force read event."""
        wait_notify = asyncio.create_task(packet_num_queue.get(), name="wait_notify")
        wait_force_read = asyncio.create_task(force_read_event.wait(), name="wait_force_read")

        done, pending = await asyncio.wait(
            {wait_notify, wait_force_read},
            timeout=notify_timeout_duration,
            return_when=asyncio.FIRST_COMPLETED,
        )

        # Ensure pending tasks are cancelled before proceeding
        for task in pending:
            task.cancel()
            with suppress(asyncio.CancelledError):
                await task

        continue_active_read = False
        if wait_force_read in done:
            self._logger.debug("Force read event received. Continuing loop for active read.")
            force_read_event.clear()
            notify_timeout_count = 0  # Reset timeout counter
            continue_active_read = True
        elif wait_notify in done:
            self._logger.debug("Packet notification received. Will attempt read.")
            _ = wait_notify.result()
            notify_timeout_count = 0  # Reset timeout counter
        else:  # Timeout occurred
            notify_timeout_count += 1
            if notify_timeout_count > max_notify_timeouts_before_restart:
                self._logger.debug(
                    "No bluetooth notification for %d times after %ds timeout, restarting notifications",
                    notify_timeout_count,
                    notify_timeout_duration,
                )
                notify_timeout_count = 0
                await restart_notify_func()
            # continue with active read
            continue_active_read = True

        return continue_active_read, notify_timeout_count

    async def _packet_stream(self) -> AsyncGenerator[mesh_pb2.FromRadio, Any]:  # noqa: PLR0915
        if not self.is_connected:
            return
        packet_num_queue = asyncio.Queue()
        force_read_event = self._force_read_event

        def notification_handler(_: BleakGATTCharacteristic, data: bytearray) -> None:
            nums = struct.unpack("<I", data)
            num = nums[0]

            if num != self._last_packet_number:
                self._last_packet_number = num
                self._logger.debug("New packet available: %s", num)
                packet_num_queue.put_nowait(num)
            else:
                self._logger.debug("Duplicate packet notification: %s", num)

        try:

            async def start_notify() -> None:
                async with self._notify_lock:
                    if self._notify_started:
                        return

                    if self._bleak_client is None or self._ble_from_num is None:
                        raise RuntimeError("BLE client or characteristic not initialized")

                    await asyncio.wait_for(
                        self._bleak_client.start_notify(
                            self._ble_from_num,
                            notification_handler,
                            bluez=BlueZStartNotifyArgs(use_start_notify=True),
                        ),
                        timeout=30,
                    )
                    self._notify_started = True

            async def stop_notify() -> None:
                async with self._notify_lock:
                    if not self._notify_started:
                        return

                    if self._bleak_client is None or self._ble_from_num is None:
                        self._notify_started = False
                        return

                    with suppress(bleak.BleakError, BleakDBusError, TimeoutError):
                        await asyncio.wait_for(
                            self._bleak_client.stop_notify(self._ble_from_num),
                            timeout=10,
                        )

                    self._notify_started = False

            async def restart_notify() -> None:
                async with self._notify_lock:
                    if self._bleak_client is None or self._ble_from_num is None:
                        raise RuntimeError("BLE client or characteristic not initialized")

                    if self._notify_started:
                        with suppress(bleak.BleakError, BleakDBusError, TimeoutError):
                            await asyncio.wait_for(
                                self._bleak_client.stop_notify(self._ble_from_num),
                                timeout=10,
                            )
                        self._notify_started = False
                    await asyncio.wait_for(
                        self._bleak_client.start_notify(
                            self._ble_from_num,
                            notification_handler,
                            bluez=BlueZStartNotifyArgs(use_start_notify=True),
                        ),
                        timeout=30,
                    )
                    self._notify_started = True

            await start_notify()

            notify_timeout_count = 0
            notify_timeout_duration = 300
            max_notify_timeouts_before_restart = 2
            while True:
                packet = await self._bleak_client.read_gatt_char(self._ble_from_radio)
                if not isinstance(packet, bytes):
                    packet = bytes(packet)
                if packet == b"":
                    # no more packets available, waiting for notification or force_read event.
                    # if we do not receive bluetooth notifications for an extended period of time, this could be an
                    # indication of issue with bluetooth stack, so we try to do an active read. This will either trigger
                    # an error or help resume sending of data by the firmware. If this happens too often, we try to
                    # re-start notifications.
                    continue_active_read, notify_timeout_count = await self._handle_notify_wait(
                        packet_num_queue,
                        force_read_event,
                        notify_timeout_duration,
                        notify_timeout_count,
                        max_notify_timeouts_before_restart,
                        restart_notify,
                    )
                    if continue_active_read:
                        continue

                elif notify_timeout_count > 0:
                    self._logger.debug(
                        "Read returned packet after ble notify timeout, maybe notifications from device have stopped"
                    )

                from_radio = mesh_pb2.FromRadio()
                try:
                    from_radio.ParseFromString(packet)
                    self._logger.debug("Parsed packet: %s", self._protobuf_log(from_radio))
                    yield from_radio
                except message.DecodeError:
                    self._logger.warning("Error while parsing FromRadio bytes %s", packet, exc_info=True)
        except BleakError as e:
            raise BluetoothConnectionError from e
        finally:
            with suppress(BleakError, BleakDBusError, RuntimeError, TimeoutError):
                await stop_notify()

    async def _send_packet(self, data: bytes) -> bool:
        if self._bleak_client is None or self._ble_to_radio is None or not self._bleak_client.is_connected:
            raise ClientApiNotConnectedError

        # Check if this packet requires a forced read
        try:
            to_radio = mesh_pb2.ToRadio()
            to_radio.ParseFromString(data)
            if to_radio.HasField("want_config_id"):
                self._logger.debug("want_config_id detected, setting force read event.")
                self._force_read_event.set()
        except message.DecodeError:
            self._logger.warning("Could not parse ToRadio packet in _send_packet to check for want_config_id.")

        async with self._write_lock:
            try:
                await self._bleak_client.write_gatt_char(self._ble_to_radio, data)
            except bleak.BleakError:
                self._logger.debug("Failed to send data", exc_info=True)
                return False
            else:
                return True
