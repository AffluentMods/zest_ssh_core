// SPDX-License-Identifier: MIT
import 'dart:typed_data';

import 'package:zest_ssh_core/src/sftp/sftp_file_attrs.dart';
import 'package:zest_ssh_core/src/sftp/sftp_name.dart';
import 'package:zest_ssh_core/src/sftp/sftp_packet.dart';
import 'package:test/test.dart';

/// The SFTP requests about paths and attributes that the other roundtrip
/// tests leave out: each decodes to what was encoded, with its packet type
/// first, and says what it is in its text.
void main() {
  final attrs = SftpFileAttrs(
    size: 4096,
    userID: 501,
    groupID: 20,
    mode: const SftpFileMode.value(0x4000 | 0x1ED),
    accessTime: 1700000000,
    modifyTime: 1700000001,
  );
  final handle = Uint8List.fromList([9, 8, 7]);

  void typed(Uint8List bytes, int type) => expect(bytes.first, type);

  test('setstat and fsetstat carry the attributes', () {
    final set = SftpSetStatPacket(10, '/srv/app', attrs);
    typed(set.encode(), SftpSetStatPacket.packetType);
    final setBack = SftpSetStatPacket.decode(set.encode());
    expect((setBack.requestId, setBack.path, setBack.attributes.size),
        (10, '/srv/app', 4096));
    expect(setBack.attributes.mode?.value, 0x4000 | 0x1ED);
    expect(set.toString(), contains('SftpSetStatPacket'));

    final fset = SftpFSetStatPacket(11, handle, attrs);
    typed(fset.encode(), SftpFSetStatPacket.packetType);
    final fsetBack = SftpFSetStatPacket.decode(fset.encode());
    expect((fsetBack.requestId, fsetBack.attributes.userID), (11, 501));
    expect(fsetBack.handle, handle);
    expect(fset.toString(), contains('SftpFSetStatPacket'));
  });

  test('mkdir, rmdir, realpath, stat and readlink carry their path', () {
    final mkdir = SftpMkdirPacket(12, '/srv/new', attrs);
    final mkdirBack = SftpMkdirPacket.decode(mkdir.encode());
    typed(mkdir.encode(), SftpMkdirPacket.packetType);
    expect((mkdirBack.requestId, mkdirBack.path, mkdirBack.attributes.groupID),
        (12, '/srv/new', 20));
    expect(mkdir.toString(), contains('/srv/new'));

    final rmdir = SftpRmdirPacket(13, '/srv/old');
    typed(rmdir.encode(), SftpRmdirPacket.packetType);
    final rmdirBack = SftpRmdirPacket.decode(rmdir.encode());
    expect((rmdirBack.requestId, rmdirBack.path), (13, '/srv/old'));
    expect(rmdir.toString(), contains('/srv/old'));

    final realpath = SftpRealpathPacket(14, '.');
    typed(realpath.encode(), SftpRealpathPacket.packetType);
    final realpathBack = SftpRealpathPacket.decode(realpath.encode());
    expect((realpathBack.requestId, realpathBack.path), (14, '.'));
    expect(realpath.toString(), contains('SftpRealpathPacket'));

    final stat = SftpStatPacket(15, '/etc/hostname');
    typed(stat.encode(), SftpStatPacket.packetType);
    final statBack = SftpStatPacket.decode(stat.encode());
    expect((statBack.requestId, statBack.path), (15, '/etc/hostname'));
    expect(stat.toString(), contains('/etc/hostname'));

    final readlink = SftpReadlinkPacket(16, '/usr/bin/python');
    typed(readlink.encode(), SftpReadlinkPacket.packetType);
    final readlinkBack = SftpReadlinkPacket.decode(readlink.encode());
    expect(
        (readlinkBack.requestId, readlinkBack.path), (16, '/usr/bin/python'));
    expect(readlink.toString(), contains('/usr/bin/python'));
  });

  test('symlink keeps which path is the link and which the target', () {
    final link = SftpSymlinkPacket(17, '/srv/current', '/srv/releases/42');
    typed(link.encode(), SftpSymlinkPacket.packetType);
    final back = SftpSymlinkPacket.decode(link.encode());
    expect((back.requestId, back.linkPath, back.targetPath),
        (17, '/srv/current', '/srv/releases/42'));
    expect(link.toString(), contains('/srv/releases/42'));
  });

  test('every packet says what it is', () {
    final names = [
      SftpName(filename: 'a.txt', longname: '-rw-r--r-- a.txt', attr: attrs)
    ];
    final packets = <Object>[
      SftpInitPacket(3),
      SftpVersionPacket(3),
      SftpOpenPacket(1, '/a', 1, attrs),
      SftpClosePacket(2, handle),
      SftpReadPacket(requestId: 3, handle: handle, offset: 0, length: 1),
      SftpWritePacket(
          requestId: 4, handle: handle, offset: 0, data: Uint8List(1)),
      SftpLStatPacket(5, '/a'),
      SftpFStatPacket(6, handle),
      SftpOpenDirPacket(7, '/'),
      SftpReadDirPacket(8, handle),
      SftpRemovePacket(9, '/a'),
      SftpRenamePacket(10, '/a', '/b'),
      SftpStatusPacket(requestId: 11, code: 0, message: 'ok'),
      SftpHandlePacket(12, handle),
      SftpDataPacket(13, Uint8List(2)),
      SftpNamePacket(14, names),
      SftpAttrsPacket(15, attrs),
      SftpExtendedPacket(16, Uint8List(1)),
      SftpExtendedReplyPacket(17, Uint8List(1)),
    ];
    for (final p in packets) {
      expect(p.toString(), startsWith(p.runtimeType.toString()),
          reason: '${p.runtimeType}');
    }
  });
}
