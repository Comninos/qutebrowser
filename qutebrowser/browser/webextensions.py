# SPDX-FileCopyrightText: Freya Bruhin (The Compiler) <mail@qutebrowser.org>
#
# SPDX-License-Identifier: GPL-3.0-or-later

"""Management of Chromium WebExtensions via QtWebEngine 6.10+."""

import base64
import hashlib
import io
import json
import os
import pathlib
import shutil
import struct
import zipfile
from collections.abc import Iterator
from typing import TYPE_CHECKING, Any

from qutebrowser.qt import machinery
from qutebrowser.qt.core import QUrl

from qutebrowser.api import cmdutils
from qutebrowser.completion.models import miscmodels
from qutebrowser.utils import log, message, objreg, standarddir, usertypes

if TYPE_CHECKING:
    from qutebrowser.qt.webenginecore import (QWebEngineExtensionInfo,
                                              QWebEngineExtensionManager)


UNPACKED_DIR_NAME = 'webextensions'

_CRX_MAGIC = b'Cr24'
_CRX_VERSION = 3

_CRASH_WARNING = (
    "Enabling/disabling extensions is known to crash QtWebEngine 6.10 and 6.11, "
    "taking qutebrowser down with it. Use --force to try anyway.")

_signals_connected = False


class CrxError(Exception):

    """Raised when a .crx file can't be parsed."""


def _read_varint(data: bytes, pos: int) -> tuple[int, int]:
    result = 0
    shift = 0
    while True:
        if pos >= len(data):
            raise CrxError("Truncated varint in CRX header")
        byte = data[pos]
        pos += 1
        result |= (byte & 0x7f) << shift
        if not byte & 0x80:
            return result, pos
        shift += 7


def _protobuf_fields(data: bytes) -> Iterator[tuple[int, Any]]:
    """Yield (field number, value) pairs of a serialized protobuf message.

    Only as much of the wire format as needed for CRX3 headers is supported.
    """
    pos = 0
    while pos < len(data):
        key, pos = _read_varint(data, pos)
        number, wire_type = key >> 3, key & 0x7
        value: int | bytes
        if wire_type == 0:
            value, pos = _read_varint(data, pos)
        elif wire_type == 1:
            value, pos = data[pos:pos + 8], pos + 8
        elif wire_type == 2:
            length, pos = _read_varint(data, pos)
            value, pos = data[pos:pos + length], pos + length
        elif wire_type == 5:
            value, pos = data[pos:pos + 4], pos + 4
        else:
            raise CrxError(f"Unsupported protobuf wire type {wire_type}")
        if pos > len(data):
            raise CrxError("Truncated CRX header")
        yield number, value


def extension_id(public_key: bytes) -> str:
    """Get the Chromium extension ID for the given DER-encoded public key."""
    digest = hashlib.sha256(public_key).hexdigest()[:32]
    return ''.join(chr(ord('a') + int(c, 16)) for c in digest)


def parse_crx(data: bytes) -> tuple[bytes, bytes]:
    """Split a CRX3 file into the extension's public key and its zip archive."""
    if data[:4] != _CRX_MAGIC:
        raise CrxError("Not a CRX file")
    if len(data) < 12:
        raise CrxError("Truncated CRX file")
    version, header_len = struct.unpack('<II', data[4:12])
    if version != _CRX_VERSION:
        raise CrxError(f"Unsupported CRX version {version}")
    header = data[12:12 + header_len]
    archive = data[12 + header_len:]

    crx_id = None
    keys = []
    for number, value in _protobuf_fields(header):
        if number in [2, 3]:  # sha256_with_rsa, sha256_with_ecdsa
            proof = dict(_protobuf_fields(value))
            if 1 in proof:
                keys.append(proof[1])
        elif number == 10000:  # signed_header_data
            crx_id = dict(_protobuf_fields(value)).get(1)

    if crx_id is None:
        raise CrxError("CRX header contains no extension ID")
    for key in keys:
        if hashlib.sha256(key).digest()[:16] == crx_id:
            return key, archive
    raise CrxError("CRX header contains no key matching the extension ID")


def unpack_crx(crx_path: pathlib.Path, target_base: pathlib.Path) -> pathlib.Path:
    """Unpack a CRX3 file, keeping its extension ID.

    The public key is added to the manifest so that the unpacked extension gets
    the same ID as the one from the store, which some extensions rely on.
    """
    public_key, archive = parse_crx(crx_path.read_bytes())
    target = target_base / extension_id(public_key)
    if target.exists():
        shutil.rmtree(target)

    try:
        with zipfile.ZipFile(io.BytesIO(archive)) as zf:
            zf.extractall(target)
    except zipfile.BadZipFile as e:
        raise CrxError(f"Invalid archive in CRX file: {e}")

    manifest_path = target / 'manifest.json'
    try:
        manifest = json.loads(manifest_path.read_text(encoding='utf-8-sig'))
    except (OSError, ValueError) as e:
        raise CrxError(f"Failed to read manifest.json: {e}")
    if 'key' not in manifest:
        manifest['key'] = base64.b64encode(public_key).decode('ascii')
        manifest_path.write_text(json.dumps(manifest, indent=2), encoding='utf-8')

    return target


def _on_finished(action: str, info: 'QWebEngineExtensionInfo') -> None:
    if info.error():
        message.error(f"Failed to {action} extension from {info.path()}: "
                      f"{info.error()}")
        return
    log.webview.debug(f"Extension {action} finished: {info.name()} ({info.id()})")
    message.info(f"Extension {action} finished: {info.name()} ({info.id()})")


def manager() -> 'QWebEngineExtensionManager':
    """Get the extension manager of the default profile."""
    if not machinery.IS_QT6:
        raise cmdutils.CommandError("WebExtensions require Qt 6")

    from qutebrowser.browser.webengine import webenginesettings
    profile = webenginesettings.default_profile
    try:
        ext_manager = profile.extensionManager()
    except AttributeError:
        raise cmdutils.CommandError("WebExtensions require QtWebEngine 6.10+")
    assert ext_manager is not None

    global _signals_connected
    if not _signals_connected:
        ext_manager.loadFinished.connect(
            lambda info: _on_finished('load', info))
        ext_manager.installFinished.connect(
            lambda info: _on_finished('install', info))
        ext_manager.unloadFinished.connect(
            lambda info: _on_finished('unload', info))
        ext_manager.uninstallFinished.connect(
            lambda info: _on_finished('uninstall', info))
        _signals_connected = True

    return ext_manager


def _find(ext_manager: 'QWebEngineExtensionManager',
          ext_id: str) -> 'QWebEngineExtensionInfo':
    for info in ext_manager.extensions():
        if info.id() == ext_id:
            return info
    raise cmdutils.CommandError(f"No extension with ID {ext_id}")


def _resolve_path(path: str) -> str:
    """Expand the given path and unpack it first if it's a .crx file."""
    resolved = pathlib.Path(os.path.expanduser(path))
    if not resolved.is_absolute():
        raise cmdutils.CommandError(f"Path must be absolute: {path}")
    if not resolved.exists():
        raise cmdutils.CommandError(f"Path does not exist: {path}")

    if resolved.suffix.lower() == '.crx':
        target_base = pathlib.Path(standarddir.data()) / UNPACKED_DIR_NAME
        try:
            resolved = unpack_crx(resolved, target_base)
        except (CrxError, OSError) as e:
            raise cmdutils.CommandError(f"Failed to unpack {path}: {e}")
        log.webview.debug(f"Unpacked {path} to {resolved}")

    return str(resolved)


@cmdutils.register(backend=usertypes.Backend.QtWebEngine)
def extension_load(path: str) -> None:
    """Load an unpacked WebExtension until qutebrowser is restarted.

    Extensions are loaded disabled, see `:extension-enable`.

    Args:
        path: Absolute path to an unpacked extension directory or a .crx file.
    """
    manager().loadExtension(_resolve_path(path))


@cmdutils.register(backend=usertypes.Backend.QtWebEngine)
def extension_install(path: str) -> None:
    """Install a WebExtension so it gets loaded on every start.

    Extensions are loaded disabled, see `:extension-enable`.

    Args:
        path: Absolute path to an unpacked extension directory, a .zip or a .crx
              file.
    """
    manager().installExtension(_resolve_path(path))


@cmdutils.register(backend=usertypes.Backend.QtWebEngine)
@cmdutils.argument('ext_id', completion=miscmodels.webextension)
def extension_unload(ext_id: str) -> None:
    """Unload a WebExtension.

    Installed extensions will be loaded again on the next start.

    Args:
        ext_id: The ID of the extension.
    """
    ext_manager = manager()
    ext_manager.unloadExtension(_find(ext_manager, ext_id))


@cmdutils.register(backend=usertypes.Backend.QtWebEngine)
@cmdutils.argument('ext_id', completion=miscmodels.webextension)
def extension_uninstall(ext_id: str) -> None:
    """Uninstall a WebExtension and remove its files.

    Args:
        ext_id: The ID of the extension.
    """
    ext_manager = manager()
    ext_manager.uninstallExtension(_find(ext_manager, ext_id))


def _set_enabled(ext_id: str, enabled: bool, force: bool) -> None:
    if not force:
        raise cmdutils.CommandError(_CRASH_WARNING)
    ext_manager = manager()
    ext_manager.setExtensionEnabled(_find(ext_manager, ext_id), enabled)


@cmdutils.register(backend=usertypes.Backend.QtWebEngine)
@cmdutils.argument('ext_id', completion=miscmodels.webextension)
def extension_enable(ext_id: str, force: bool = False) -> None:
    """Enable a loaded WebExtension.

    Args:
        ext_id: The ID of the extension.
        force: Enable it even though this is known to crash QtWebEngine.
    """
    _set_enabled(ext_id, enabled=True, force=force)


@cmdutils.register(backend=usertypes.Backend.QtWebEngine)
@cmdutils.argument('ext_id', completion=miscmodels.webextension)
def extension_disable(ext_id: str, force: bool = False) -> None:
    """Disable a loaded WebExtension.

    Args:
        ext_id: The ID of the extension.
        force: Disable it even though this is known to crash QtWebEngine.
    """
    _set_enabled(ext_id, enabled=False, force=force)


@cmdutils.register(backend=usertypes.Backend.QtWebEngine)
@cmdutils.argument('ext_id', completion=miscmodels.webextension)
@cmdutils.argument('win_id', value=cmdutils.Value.win_id)
def extension_popup(ext_id: str, win_id: int, bg: bool = False) -> None:
    """Open the toolbar popup of a WebExtension in a new tab.

    Args:
        ext_id: The ID of the extension.
        bg: Open in a background tab.
    """
    info = _find(manager(), ext_id)
    url = info.actionPopupUrl()
    if not url.isValid():
        raise cmdutils.CommandError(f"{info.name()} has no popup")
    tabbed_browser = objreg.get('tabbed-browser', scope='window', window=win_id)
    tabbed_browser.tabopen(QUrl(url), background=bg, related=False)
