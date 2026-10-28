import 'package:flutter/material.dart';

/// Build-time configuration, supplied with `--dart-define`.
///
/// Nothing secret is configured here: the client never holds API keys.
/// Institutions customise branding (name, accent colour) per deployment.
class AppConfig {
  const AppConfig({
    required this.apiBaseUrl,
    required this.institutionName,
    required this.countryCode,
    required this.accentColor,
    required this.mapTileUrl,
    required this.allowInsecureHttpForDev,
  });

  final String apiBaseUrl;
  final String institutionName;
  final String countryCode;
  final Color accentColor;

  /// Institutional tile server. Empty means no base map is fetched at all,
  /// so no third party learns which areas are being looked at.
  final String mapTileUrl;
  final bool allowInsecureHttpForDev;

  static AppConfig fromEnvironment() {
    const accent = String.fromEnvironment('AIC_ACCENT', defaultValue: '2F7DF6');
    return AppConfig(
      apiBaseUrl: const String.fromEnvironment('AIC_API_BASE_URL', defaultValue: 'https://api.aic.invalid/api/v1'),
      institutionName: const String.fromEnvironment('AIC_INSTITUTION', defaultValue: 'AFRICAN INTELLIGENCE CORE'),
      countryCode: const String.fromEnvironment('AIC_COUNTRY', defaultValue: 'XX'),
      accentColor: Color(int.parse('FF$accent', radix: 16)),
      mapTileUrl: const String.fromEnvironment('AIC_MAP_TILES', defaultValue: ''),
      allowInsecureHttpForDev: const bool.fromEnvironment('AIC_DEV_ALLOW_HTTP', defaultValue: false),
    );
  }

  /// Refuses plain HTTP except for an explicit development flag on loopback hosts.
  void validate() {
    final uri = Uri.parse(apiBaseUrl);
    final loopback = {'localhost', '127.0.0.1', '10.0.2.2'}.contains(uri.host);
    if (uri.scheme != 'https' && !(allowInsecureHttpForDev && loopback)) {
      throw StateError('AIC_API_BASE_URL must use HTTPS');
    }
  }
}
