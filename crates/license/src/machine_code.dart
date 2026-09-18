import 'dart:convert';
import 'dart:io';

import 'package:pointycastle/digests/sha256.dart';

/// 机器码——离线授权绑机用。
///
/// 原始硬件 ID：Windows 读注册表 MachineGuid，macOS 读 IOPlatformUUID。
/// 展示与写进 license 的只是加盐哈希，不泄露原始硬件 ID。
/// 注：此处运行时平台判断是「选哪条 shell 命令」，
/// 与 sqlite_tree_builder.dart 的 open/xdg-open/explorer 同理；
/// 直销构建无沙盒可 shell，MAS 沙盒构建读取会失败并返回 null
/// （该构建下离线授权 UI 被 DIRECT_BUILD 门控，不受影响）。
class MachineCode {
  MachineCode._();

  /// 加盐前缀——防彩虹表，且把机器码命名空间限定到本应用。
  static const String _salt = 'dbmaster:';

  /// 机器码展示长度（hex 字符数 = sha256 前 16 字节）。
  static const int codeLength = 32;

  /// 读取当前机器的机器码；不支持的平台或读取失败返回 null。
  static Future<String?> currentMachineCode() async {
    final raw = await readRawMachineId();
    if (raw == null) return null;
    return toMachineCode(raw);
  }

  /// 读取原始硬件 ID；任何失败（命令不存在/沙盒拒绝/解析失败）返回 null。
  static Future<String?> readRawMachineId() async {
    try {
      if (Platform.isWindows) {
        final result = await Process.run(
          'reg',
          const ['query', r'HKLM\SOFTWARE\Microsoft\Cryptography', '/v', 'MachineGuid'],
        );
        if (result.exitCode != 0) return null;
        return parseRegQueryOutput(result.stdout as String);
      }
      if (Platform.isMacOS) {
        final result = await Process.run(
          'ioreg',
          const ['-rd1', '-c', 'IOPlatformExpertDevice'],
        );
        if (result.exitCode != 0) return null;
        return parseIoregOutput(result.stdout as String);
      }
      return null;
    } on ProcessException {
      return null;
    }
  }

  /// 解析 `reg query ... /v MachineGuid` 输出（REG_SZ 令牌各语言系统不变）。
  static String? parseRegQueryOutput(String output) {
    for (final line in output.split(RegExp(r'\r?\n'))) {
      final trimmed = line.trim();
      if (!trimmed.startsWith('MachineGuid')) continue;
      final match = RegExp(r'REG_SZ\s+(\S+)').firstMatch(trimmed);
      final value = match?.group(1)?.trim();
      if (value != null && value.isNotEmpty) return value;
    }
    return null;
  }

  /// 解析 `ioreg -rd1 -c IOPlatformExpertDevice` 输出中的 IOPlatformUUID。
  static String? parseIoregOutput(String output) {
    final match =
        RegExp(r'"IOPlatformUUID"\s*=\s*"([^"]+)"').firstMatch(output);
    final value = match?.group(1)?.trim();
    return (value != null && value.isNotEmpty) ? value : null;
  }

  /// 原始 ID → 机器码：`hex(sha256('dbmaster:' + rawId))` 前 [codeLength] 字符。
  static String toMachineCode(String rawId) {
    final digest =
        SHA256Digest().process(utf8.encode('$_salt${rawId.trim()}'));
    final hex = digest.map((b) => b.toRadixString(16).padLeft(2, '0')).join();
    return hex.substring(0, codeLength);
  }
}
