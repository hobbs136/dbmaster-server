import 'dart:convert';

import 'package:cryptography/cryptography.dart';

import 'package:dbmaster/pro/shared/license_models.dart';

/// 验签结果状态。
enum LicenseVerifyStatus {
  ok,
  invalidFormat,
  badSignature,
  machineMismatch,
  expired,
  machineUnavailable, // 本机机器码读不到（沙盒/不支持的平台）
}

/// 验签结果；[status] 为 ok 时 [payload] 必有值。
class LicenseVerifyResult {
  const LicenseVerifyResult(this.status, [this.payload]);

  final LicenseVerifyStatus status;
  final LicensePayload? payload;

  bool get isOk => status == LicenseVerifyStatus.ok;
}

/// 离线授权验签器（纯函数，无 I/O、不读机器码）。
///
/// license 字符串格式：`base64url(payloadJson).base64url(signature)`，
/// 签名消息 = payload 段的 ASCII 字节（避免 JSON 规范化歧义）。
class LicenseVerifier {
  const LicenseVerifier({this.publicKeyHex = embeddedPublicKeyHex});

  /// 内置公钥（真实密钥对，2026-07-19 `dart run bin/license_signer.dart keygen`
  /// 生成）。私钥只保存在签发方机器（private_key.hex，已 gitignore），禁止入库。
  static const String embeddedPublicKeyHex =
      '5041f821e42c930606ca3e36449f31b574fe4f84514fffffa31ba6a05cc3865a';

  /// 可注入的公钥（测试用）；默认用内置常量。
  final String publicKeyHex;

  Future<LicenseVerifyResult> verify(
    String licenseStr, {
    required String machineCode,
    DateTime? now,
  }) async {
    final trimmed = licenseStr.trim();
    final dot = trimmed.indexOf('.');
    if (dot <= 0 || dot == trimmed.length - 1 || trimmed.indexOf('.', dot + 1) != -1) {
      return const LicenseVerifyResult(LicenseVerifyStatus.invalidFormat);
    }
    final payloadSegment = trimmed.substring(0, dot);
    final signatureSegment = trimmed.substring(dot + 1);

    final payloadJson = _base64UrlDecodeToString(payloadSegment);
    final signatureBytes = _base64UrlDecodeToBytes(signatureSegment);
    final publicKeyBytes = _hexDecode(publicKeyHex);
    if (payloadJson == null ||
        signatureBytes == null ||
        publicKeyBytes == null ||
        signatureBytes.length != 64 ||
        publicKeyBytes.length != 32) {
      return const LicenseVerifyResult(LicenseVerifyStatus.invalidFormat);
    }

    final LicensePayload payload;
    try {
      payload = LicensePayload.fromCanonicalJson(payloadJson);
    } on FormatException {
      return const LicenseVerifyResult(LicenseVerifyStatus.invalidFormat);
    }

    final algorithm = Ed25519();
    final isValid = await algorithm.verify(
      ascii.encode(payloadSegment),
      signature: Signature(
        signatureBytes,
        publicKey: SimplePublicKey(publicKeyBytes, type: KeyPairType.ed25519),
      ),
    );
    if (!isValid) {
      return const LicenseVerifyResult(LicenseVerifyStatus.badSignature);
    }
    if (payload.machine != machineCode) {
      return LicenseVerifyResult(LicenseVerifyStatus.machineMismatch, payload);
    }
    final effectiveNow = (now ?? DateTime.now()).toUtc();
    final expiresAt = payload.expiresAt;
    if (expiresAt != null && !effectiveNow.isBefore(expiresAt)) {
      return LicenseVerifyResult(LicenseVerifyStatus.expired, payload);
    }
    return LicenseVerifyResult(LicenseVerifyStatus.ok, payload);
  }

  static String? _base64UrlDecodeToString(String segment) {
    final bytes = _base64UrlDecodeToBytes(segment);
    if (bytes == null) return null;
    try {
      return utf8.decode(bytes);
    } on FormatException {
      return null;
    }
  }

  /// base64url 解码（容忍缺 padding），非法输入返回 null。
  static List<int>? _base64UrlDecodeToBytes(String segment) {
    if (segment.isEmpty) return null;
    try {
      return base64Url.decode(base64Url.normalize(segment));
    } on FormatException {
      return null;
    }
  }

  static List<int>? _hexDecode(String hex) {
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
}
