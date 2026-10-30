# SPDX-License-Identifier: AGPL-3.0-only
"""Local QEMU control channels; guest network/resource tests are unchanged."""
from functools import lru_cache
import os
import socket


@lru_cache(maxsize=8)
def endpoint(path):
    if os.environ.get('RYZOVA_QEMU_LOOPBACK') != '1':
        return socket.AF_UNIX, str(path)
    # QEMU binds only loopback. Release the ephemeral reservation immediately;
    # an intervening collision is a startup failure, never a public bind.
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as reservation:
        reservation.bind(('127.0.0.1', 0))
        address = reservation.getsockname()
    return socket.AF_INET, address


def control_socket(path):
    return socket.socket(endpoint(str(path))[0], socket.SOCK_STREAM)


def control_address(path):
    return endpoint(str(path))[1]


def serial_option(path):
    family, address = endpoint(str(path))
    location = f'host={address[0]},port={address[1]}' if family == socket.AF_INET else f'path={address}'
    return f'socket,id=uart,{location},server=on,wait=off'


def monitor_option(path):
    family, address = endpoint(str(path))
    location = f'tcp:{address[0]}:{address[1]}' if family == socket.AF_INET else f'unix:{address}'
    return f'{location},server=on,wait=off'
