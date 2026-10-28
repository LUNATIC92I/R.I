import 'dart:io';

import 'package:flutter/foundation.dart';
import 'package:flutter/material.dart';
import 'package:path_provider/path_provider.dart';

import 'app.dart';
import 'core/api/api_client.dart';
import 'core/auth/auth_controller.dart';
import 'core/auth/biometric_gate.dart';
import 'core/auth/token_store.dart';
import 'core/config.dart';
import 'core/offline/encrypted_cache.dart';
import 'core/offline/offline_service.dart';
import 'core/security/device_identity.dart';
import 'core/security/secure_store.dart';
import 'core/services.dart';

Future<void> main() async {
  WidgetsFlutterBinding.ensureInitialized();
  // Never print errors containing payloads in release builds.
  if (kReleaseMode) debugPrint = (String? message, {int? wrapWidth}) {};

  final config = AppConfig.fromEnvironment()..validate();
  final store = SecureStore();
  final tokens = TokenStore(store);
  final api = ApiClient(baseUrl: config.apiBaseUrl, tokens: tokens);
  final cacheDir = Directory('${(await getApplicationSupportDirectory()).path}/aic_cache');
  final cache = EncryptedCache(directory: cacheDir, keyStore: store);
  final auth = AuthController(
    api: api,
    tokens: tokens,
    device: DeviceIdentity(store),
    biometric: LocalBiometricGate(),
    cache: cache,
  );
  final services = AppServices(
    config: config,
    api: api,
    auth: auth,
    offline: OfflineService(api, cache),
    locale: ValueNotifier<Locale?>(null),
    child: const SizedBox.shrink(),
  );
  runApp(AicApp(services: services));
  await auth.start();
}
