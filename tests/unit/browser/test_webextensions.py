# SPDX-FileCopyrightText: Freya Bruhin (The Compiler) <mail@qutebrowser.org>
#
# SPDX-License-Identifier: GPL-3.0-or-later

import base64
import hashlib
import io
import json
import struct
import zipfile

import pytest
from qutebrowser.qt.core import QUrl

from qutebrowser.api import cmdutils
from qutebrowser.browser import webextensions


PROTON_PASS_KEY = (
    "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAiZt8pKnvrDkvOuKzjfj1TtrPc0lw"
    "lUc/pvAOAoLmtQ9i5IdVisA7m4zqLKFONapyI3FWPsThpGRteYpLSgIf0LY8E2TGCHRDobYM"
    "LagS7OAbVySapvYCqj4LBQ7EOSYNVOEOUgyTAWqDB4udB6vgQXkRV6f2n2hAsAvrkutW1U4U"
    "novg1zksp24bOTwyOxM5rJ6vbqGVzuhiblqaOpinmN+TQ53+8xCmVduWrQCMO3I+/hOPmw6S"
    "9nPMFj1Wsc+qIsNMCLT8kEGRGa51gw7ZK7TaYQ1MGB/O+lbUjcL5bjYYvcYXA7bL3Ol8vhSL"
    "N5yhhxox9w19O/+bwoyib4OAHQIDAQAB"
)
PROTON_PASS_ID = "ghmbeldphafepmbegfdlkpapadhbakde"

FAKE_KEY = b"not-really-a-der-key"


def _varint(value: int) -> bytes:
    out = bytearray()
    while True:
        byte = value & 0x7f
        value >>= 7
        if value:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return bytes(out)


def _field(number: int, value: bytes) -> bytes:
    return _varint(number << 3 | 2) + _varint(len(value)) + value


def _make_zip(manifest: dict) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w') as zf:
        zf.writestr('manifest.json', json.dumps(manifest))
        zf.writestr('popup.html', '<html></html>')
    return buf.getvalue()


def _make_crx(
    archive: bytes,
    *,
    key: bytes = FAKE_KEY,
    crx_id: bytes | None = None,
    magic: bytes = b'Cr24',
    version: int = 3,
) -> bytes:
    if crx_id is None:
        crx_id = hashlib.sha256(key).digest()[:16]
    header = (
        _field(2, _field(1, b"some-other-key") + _field(2, b"sig"))
        + _field(2, _field(1, key) + _field(2, b"sig"))
        + _field(10000, _field(1, crx_id))
    )
    return magic + struct.pack('<II', version, len(header)) + header + archive


def test_extension_id():
    assert webextensions.extension_id(base64.b64decode(PROTON_PASS_KEY)) == PROTON_PASS_ID


def test_parse_crx():
    archive = _make_zip({'name': 'test'})
    key, parsed_archive = webextensions.parse_crx(_make_crx(archive))
    assert key == FAKE_KEY
    assert parsed_archive == archive


@pytest.mark.parametrize('kwargs, match', [
    ({'magic': b'PK\x03\x04'}, "Not a CRX file"),
    ({'version': 2}, "Unsupported CRX version 2"),
    ({'crx_id': b'\x00' * 16}, "no key matching"),
])
def test_parse_crx_invalid(kwargs, match):
    with pytest.raises(webextensions.CrxError, match=match):
        webextensions.parse_crx(_make_crx(b'', **kwargs))


def test_parse_crx_truncated():
    with pytest.raises(webextensions.CrxError):
        webextensions.parse_crx(b'Cr24\x03\x00\x00\x00\xff\x00\x00\x00\x12\xff')


def test_unpack_crx_injects_key(tmp_path):
    crx = tmp_path / 'ext.crx'
    crx.write_bytes(_make_crx(_make_zip({'name': 'test'})))

    target = webextensions.unpack_crx(crx, tmp_path / 'out')

    assert target.name == webextensions.extension_id(FAKE_KEY)
    manifest = json.loads((target / 'manifest.json').read_text('utf-8'))
    assert manifest == {
        'name': 'test',
        'key': base64.b64encode(FAKE_KEY).decode('ascii'),
    }
    assert (target / 'popup.html').exists()


def test_unpack_crx_keeps_existing_key(tmp_path):
    crx = tmp_path / 'ext.crx'
    crx.write_bytes(_make_crx(_make_zip({'name': 'test', 'key': 'existing'})))
    target = webextensions.unpack_crx(crx, tmp_path / 'out')
    manifest = json.loads((target / 'manifest.json').read_text('utf-8'))
    assert manifest['key'] == 'existing'


def test_unpack_crx_replaces_old(tmp_path):
    crx = tmp_path / 'ext.crx'
    crx.write_bytes(_make_crx(_make_zip({'name': 'test'})))
    target = webextensions.unpack_crx(crx, tmp_path / 'out')
    (target / 'stale.js').write_text('')
    target = webextensions.unpack_crx(crx, tmp_path / 'out')
    assert not (target / 'stale.js').exists()


class FakeExtensionInfo:

    def __init__(self, ext_id, popup=QUrl()):
        self._id = ext_id
        self._popup = popup

    def id(self):
        return self._id

    def name(self):
        return f"{self._id} name"

    def actionPopupUrl(self):
        return self._popup


@pytest.fixture
def fake_manager(mocker, monkeypatch):
    ext_manager = mocker.Mock()
    ext_manager.extensions.return_value = [
        FakeExtensionInfo('ext1', QUrl('chrome-extension://ext1/popup.html')),
        FakeExtensionInfo('ext2'),
    ]
    monkeypatch.setattr(webextensions, 'manager', lambda: ext_manager)
    return ext_manager


def test_load(fake_manager, tmp_path):
    webextensions.extension_load(str(tmp_path))
    fake_manager.loadExtension.assert_called_once_with(str(tmp_path))


def test_install_crx(fake_manager, tmp_path, data_tmpdir):
    crx = tmp_path / 'ext.crx'
    crx.write_bytes(_make_crx(_make_zip({'name': 'test'})))

    webextensions.extension_install(str(crx))

    expected = (
        data_tmpdir / webextensions.UNPACKED_DIR_NAME
        / webextensions.extension_id(FAKE_KEY)
    )
    fake_manager.installExtension.assert_called_once_with(str(expected))


def test_install_invalid_crx(fake_manager, tmp_path, data_tmpdir):
    crx = tmp_path / 'ext.crx'
    crx.write_bytes(b'garbage')
    with pytest.raises(cmdutils.CommandError, match="Not a CRX file"):
        webextensions.extension_install(str(crx))
    fake_manager.installExtension.assert_not_called()


@pytest.mark.parametrize('relative, match', [
    (True, "Path must be absolute"),
    (False, "Path does not exist"),
])
def test_load_invalid_path(fake_manager, tmp_path, relative, match):
    path = 'relative/path' if relative else str(tmp_path / 'missing')
    with pytest.raises(cmdutils.CommandError, match=match):
        webextensions.extension_load(path)
    fake_manager.loadExtension.assert_not_called()


def test_unload(fake_manager):
    webextensions.extension_unload('ext2')
    (info,), _kwargs = fake_manager.unloadExtension.call_args
    assert info.id() == 'ext2'


def test_uninstall_unknown(fake_manager):
    with pytest.raises(cmdutils.CommandError, match="No extension with ID nope"):
        webextensions.extension_uninstall('nope')


@pytest.mark.parametrize('func, enabled', [
    (webextensions.extension_enable, True),
    (webextensions.extension_disable, False),
])
def test_set_enabled(fake_manager, func, enabled):
    with pytest.raises(cmdutils.CommandError, match="--force"):
        func('ext1')
    fake_manager.setExtensionEnabled.assert_not_called()

    func('ext1', force=True)
    (info, called_enabled), _kwargs = fake_manager.setExtensionEnabled.call_args
    assert info.id() == 'ext1'
    assert called_enabled == enabled


def test_popup(fake_manager, mocker):
    get = mocker.patch.object(webextensions.objreg, 'get')
    webextensions.extension_popup('ext1', win_id=0, bg=True)
    get.assert_called_once_with('tabbed-browser', scope='window', window=0)
    get.return_value.tabopen.assert_called_once_with(
        QUrl('chrome-extension://ext1/popup.html'), background=True, related=False)


def test_popup_missing(fake_manager):
    with pytest.raises(cmdutils.CommandError, match="ext2 name has no popup"):
        webextensions.extension_popup('ext2', win_id=0)
