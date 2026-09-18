import 'dart:convert';

/// 离线授权类型：年订阅 / 买断。
enum LicenseType {
  yearly,
  lifetime;

  static LicenseType parse(String raw) {
    for (final value in LicenseType.values) {
      if (value.name == raw) return value;
    }
    throw const FormatException('unknown license type');
  }
}

/// 离线授权 license 的签名载荷。
///
/// 序列化形式固定（[toCanonicalJson] 键序固定），签发端（bin/license_signer.dart）
/// 与验签端（license_verifier.dart）共用本类，保证两端字节一致。
class LicensePayload {
  LicensePayload({
    required this.email,
    required this.machine,
    required this.type,
    required this.issuedAt,
    this.expiresAt,
    this.version = 1,
  });

  /// 格式版本，当前恒为 1。
  final int version;

  /// 购买者邮箱（仅展示用，不参与安全判断）。
  final String email;

  /// 绑定的机器码（原始硬件 ID 的加盐哈希，见 machine_code.dart）。
  final String machine;

  final LicenseType type;

  /// 签发时间（UTC）。
  final DateTime issuedAt;

  /// 到期时间（UTC）；lifetime 为 null。
  final DateTime? expiresAt;

  /// 键序固定的 JSON 文本——签名的消息体来源。
  String toCanonicalJson() => jsonEncode(<String, Object?>{
        'v': version,
        'email': email,
        'machine': machine,
        'type': type.name,
        'issuedAt': issuedAt.toUtc().toIso8601String(),
        'expiresAt': expiresAt?.toUtc().toIso8601String(),
      });

  /// 解析并校验载荷，非法时抛 [FormatException]（由验签器归类为 invalidFormat）。
  factory LicensePayload.fromCanonicalJson(String jsonStr) {
    final Object? decoded;
    try {
      decoded = jsonDecode(jsonStr);
    } on FormatException {
      throw const FormatException('payload is not valid JSON');
    }
    if (decoded is! Map<String, dynamic>) {
      throw const FormatException('payload is not a JSON object');
    }
    final version = decoded['v'];
    final email = decoded['email'];
    final machine = decoded['machine'];
    final type = decoded['type'];
    final issuedAt = decoded['issuedAt'];
    if (version is! int || version != 1) {
      throw const FormatException('unsupported license version');
    }
    if (email is! String || email.isEmpty) {
      throw const FormatException('missing email');
    }
    if (machine is! String || machine.isEmpty) {
      throw const FormatException('missing machine code');
    }
    if (type is! String) {
      throw const FormatException('missing license type');
    }
    if (issuedAt is! String) {
      throw const FormatException('missing issuedAt');
    }
    final parsedType = LicenseType.parse(type);
    final parsedIssuedAt = DateTime.tryParse(issuedAt);
    if (parsedIssuedAt == null) {
      throw const FormatException('invalid issuedAt');
    }
    final expiresRaw = decoded['expiresAt'];
    DateTime? parsedExpires;
    if (parsedType == LicenseType.yearly) {
      if (expiresRaw is! String) {
        throw const FormatException('yearly license missing expiresAt');
      }
      parsedExpires = DateTime.tryParse(expiresRaw);
      if (parsedExpires == null) {
        throw const FormatException('invalid expiresAt');
      }
    }
    return LicensePayload(
      version: version,
      email: email,
      machine: machine,
      type: parsedType,
      issuedAt: parsedIssuedAt.toUtc(),
      expiresAt: parsedExpires?.toUtc(),
    );
  }
}
