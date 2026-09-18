// 离线授权签发 CLI（仅签发方使用，私钥永不入库、不进 App）。
//
// 用法：
//   dart run bin/license_signer.dart keygen [--force]
//     生成 Ed25519 密钥对 → private_key.hex 写入当前目录，
//     并打印公钥 hex（粘贴到 lib/services/license/license_verifier.dart
//     的 embeddedPublicKeyHex 后再打包发布）。
//   dart run bin/license_signer.dart sign
//       --machine <机器码> --email <邮箱> --type yearly|lifetime
//       [--days 365] [--key private_key.hex] [--out 授权文件名.dbmlicense]
//     输出 license 字符串；--out 时同时写文件（内容即该字符串）。

import 'dart:convert';
import 'dart:io';

import 'package:cryptography/cryptography.dart';
import 'package:dbmaster/pro/shared/license_models.dart';

const String _defaultKeyFile = 'private_key.hex';

Future<void> main(List<String> args) async {
  if (args.isEmpty) {
    _usage();
    exitCode = 64;
    return;
  }
  switch (args.first) {
    case 'keygen':
      await _keygen(force: args.contains('--force'));
    case 'sign':
      await _sign(args.sublist(1));
    default:
      stderr.writeln('未知命令: ${args.first}');
      _usage();
      exitCode = 64;
  }
}

void _usage() {
  stdout.writeln('''离线授权签发工具
  keygen [--force]                        生成密钥对（private_key.hex）
  sign --machine M --email E --type T     签发 license
       [--days 365] [--key 私钥文件] [--out 输出文件]
       T = yearly（按 --days 算到期）| lifetime（无到期）''');
}

Future<void> _keygen({required bool force}) async {
  final keyFile = File(_defaultKeyFile);
  if (keyFile.existsSync() && !force) {
    stderr.writeln('错误: $_defaultKeyFile 已存在。覆盖请加 --force（旧 key 签出的 license 将全部失效！）');
    exitCode = 65;
    return;
  }
  final algorithm = Ed25519();
  final keyPair = await algorithm.newKeyPair();
  final seed = await keyPair.extractPrivateKeyBytes();
  final publicKey = await keyPair.extractPublicKey();

  keyFile.writeAsStringSync(_hexEncode(seed));
  stdout.writeln('私钥已写入 ${keyFile.path}（请离线备份、切勿提交版本库）');
  stdout.writeln('公钥 hex（粘贴到 license_verifier.dart 的 embeddedPublicKeyHex）:');
  stdout.writeln(_hexEncode(publicKey.bytes));
}

Future<void> _sign(List<String> args) async {
  final options = _parseOptions(args);
  final machine = options['machine'];
  final email = options['email'];
  final typeRaw = options['type'];
  if (machine == null || machine.isEmpty || email == null || email.isEmpty || typeRaw == null) {
    stderr.writeln('错误: sign 需要 --machine、--email、--type');
    exitCode = 64;
    return;
  }
  final LicenseType type;
  try {
    type = LicenseType.parse(typeRaw);
  } on FormatException {
    stderr.writeln('错误: --type 只能是 yearly 或 lifetime');
    exitCode = 64;
    return;
  }
  final days = int.tryParse(options['days'] ?? '365');
  if (days == null || days <= 0) {
    stderr.writeln('错误: --days 必须是正整数');
    exitCode = 64;
    return;
  }

  final keyPath = options['key'] ?? _defaultKeyFile;
  final keyFile = File(keyPath);
  if (!keyFile.existsSync()) {
    stderr.writeln('错误: 私钥文件 $keyPath 不存在，请先运行 keygen');
    exitCode = 66;
    return;
  }
  final seed = _hexDecode(keyFile.readAsStringSync().trim());
  if (seed == null || seed.length != 32) {
    stderr.writeln('错误: 私钥文件格式非法（应为 64 个 hex 字符）');
    exitCode = 65;
    return;
  }

  final now = DateTime.now().toUtc();
  final payload = LicensePayload(
    email: email,
    machine: machine,
    type: type,
    issuedAt: now,
    expiresAt: type == LicenseType.yearly ? now.add(Duration(days: days)) : null,
  );

  final payloadSegment = base64Url
      .encode(utf8.encode(payload.toCanonicalJson()))
      .replaceAll('=', '');
  final algorithm = Ed25519();
  final keyPair = await algorithm.newKeyPairFromSeed(seed);
  final signature =
      await algorithm.sign(ascii.encode(payloadSegment), keyPair: keyPair);
  final license =
      '$payloadSegment.${base64Url.encode(signature.bytes).replaceAll('=', '')}';

  stdout.writeln(license);
  final outPath = options['out'];
  if (outPath != null) {
    File(outPath).writeAsStringSync(license);
    stdout.writeln('已写入 $outPath');
  }
}

Map<String, String> _parseOptions(List<String> args) {
  final result = <String, String>{};
  for (var i = 0; i < args.length; i++) {
    final arg = args[i];
    if (arg.startsWith('--') && i + 1 < args.length) {
      result[arg.substring(2)] = args[++i];
    }
  }
  return result;
}

String _hexEncode(List<int> bytes) =>
    bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();

List<int>? _hexDecode(String hex) {
  if (hex.isEmpty || hex.length.isOdd) return null;
  try {
    return List<int>.generate(
      hex.length ~/ 2,
      (i) => int.parse(hex.substring(i * 2, i * 2 + 2), radix: 16),
    );
  } on FormatException {
    return null;
  }
}
