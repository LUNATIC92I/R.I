import 'dart:convert';
import 'dart:io';

import 'package:aic_mobile/app.dart';
import 'package:aic_mobile/core/api/api_client.dart';
import 'package:aic_mobile/core/auth/auth_controller.dart';
import 'package:aic_mobile/core/auth/biometric_gate.dart';
import 'package:aic_mobile/core/auth/token_store.dart';
import 'package:aic_mobile/core/config.dart';
import 'package:aic_mobile/core/offline/encrypted_cache.dart';
import 'package:aic_mobile/core/offline/offline_service.dart';
import 'package:aic_mobile/core/security/device_identity.dart';
import 'package:aic_mobile/core/security/secure_store.dart';
import 'package:aic_mobile/core/services.dart';
import 'package:flutter/material.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';

class FakeBiometric implements BiometricGate {
  FakeBiometric({this.isAvailable = true, this.succeeds = true});

  bool isAvailable;
  bool succeeds;
  int calls = 0;

  @override
  Future<bool> available() async => isAvailable;

  @override
  Future<bool> authenticate(String reason) async {
    calls++;
    return succeeds;
  }
}

/// Synthetic backend: answers by "METHOD path" with JSON bodies.
class FakeBackend {
  final routes = <String, http.Response Function(http.Request)>{};
  final calls = <String>[];

  void on(String key, Object? body, {int status = 200}) =>
      routes[key] = (_) => http.Response(jsonEncode(body), status, headers: {'content-type': 'application/json'});

  MockClient get client => MockClient((req) async {
        final key = '${req.method} ${req.url.path.replaceFirst('/api/v1', '')}';
        calls.add(key);
        final handler = routes[key];
        if (handler == null) return http.Response('{"code":"not_found"}', 404);
        return handler(req);
      });
}

const testMe = {
  'id': 'u1',
  'username': 'analyste.test',
  'display_name': 'Analyste fictif',
  'professional_id': 'ANA-TEST',
  'service_id': 's1',
  'clearance_rank': 2,
  'is_active': true,
  'mfa_enrolled': true,
  'preferred_locale': 'fr',
  'roles': [
    {'code': 'analyst', 'name_fr': 'Analyste du renseignement', 'name_en': 'Intelligence analyst', 'case_scope': 'membership'},
  ],
  'permissions': ['case:read', 'case:create', 'search:use', 'statement:write'],
};

class Harness {
  Harness._(this.backend, this.store, this.services, this.biometric, this.cacheDir);

  final FakeBackend backend;
  final MemoryStore store;
  final AppServices services;
  final FakeBiometric biometric;
  final Directory cacheDir;

  AuthController get auth => services.auth;

  static Harness create({FakeBiometric? biometric}) {
    final backend = FakeBackend();
    final store = MemoryStore();
    final tokens = TokenStore(store);
    final api = ApiClient(baseUrl: 'https://api.test/api/v1', tokens: tokens, httpClient: backend.client);
    final dir = Directory.systemTemp.createTempSync('aic_test_');
    final cache = EncryptedCache(directory: Directory('${dir.path}/cache'), keyStore: store);
    final bio = biometric ?? FakeBiometric();
    final auth = AuthController(api: api, tokens: tokens, device: DeviceIdentity(store), biometric: bio, cache: cache);
    final config = AppConfig(
      apiBaseUrl: 'https://api.test/api/v1',
      institutionName: 'AFRICAN INTELLIGENCE CORE',
      countryCode: 'XX',
      accentColor: const Color(0xFF2F7DF6),
      mapTileUrl: '',
      allowInsecureHttpForDev: false,
    );
    final services = AppServices(
      config: config,
      api: api,
      auth: auth,
      offline: OfflineService(api, cache),
      locale: ValueNotifier<Locale?>(const Locale('fr')),
      child: const SizedBox.shrink(),
    );
    return Harness._(backend, store, services, bio, dir);
  }

  Widget app() => AicApp(services: services);

  void stubLogin() {
    backend.on('POST /auth/login', {'mfa_required': true, 'mfa_token': 'mfa-token-0001', 'enrollment_required': false});
    backend.on('POST /auth/mfa', {
      'access_token': 'access-1',
      'refresh_token': 'sid.refresh-1',
      'token_type': 'bearer',
      'expires_at': 0,
      'session_id': 'sid',
    });
    backend.on('GET /me', testMe);
    backend.on('GET /admin/classifications', [
      {'rank': 0, 'marking': 'NON CLASSIFIÉ / UNCLASSIFIED'},
      {'rank': 1, 'marking': 'DIFFUSION RESTREINTE / RESTRICTED'},
    ]);
    backend.on('GET /me/devices/current/status', {'status': 'active', 'wipe_requested': false});
    backend.on('GET /dashboard', {
      'scope_notice': 'Indicateurs limités aux données auxquelles vous avez accès.',
      'active_cases': 3,
      'alerts_to_verify': 1,
      'review_due_soon': [],
      'recent_events': [],
    });
    backend.on('GET /alerts', []);
    backend.on('GET /cases', []);
  }
}
