import 'dart:convert';
import 'dart:io';

import 'package:aic_mobile/core/api/api_client.dart';
import 'package:aic_mobile/core/auth/auth_controller.dart';
import 'package:aic_mobile/core/config.dart';
import 'package:aic_mobile/core/offline/encrypted_cache.dart';
import 'package:aic_mobile/core/security/secure_store.dart';
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;

import 'helpers.dart';

void main() {
  group('EncryptedCache', () {
    late Directory dir;
    late MemoryStore keys;
    late EncryptedCache cache;

    setUp(() {
      dir = Directory.systemTemp.createTempSync('aic_cache_');
      keys = MemoryStore();
      cache = EncryptedCache(directory: Directory('${dir.path}/c'), keyStore: keys);
    });

    test('round trip, ciphertext does not contain plaintext', () async {
      await cache.put('case_1', {'title': 'SECRET-FICTIF'}, expiresAt: DateTime.now().add(const Duration(hours: 1)));
      final raw = await File('${dir.path}/c/case_1.bin').readAsString(encoding: latin1);
      expect(raw.contains('SECRET-FICTIF'), isFalse);
      expect((await cache.get('case_1'))!['title'], 'SECRET-FICTIF');
    });

    test('expired entries are refused and deleted', () async {
      await cache.put('case_2', {'a': 1}, expiresAt: DateTime.now().add(const Duration(minutes: 1)));
      expect(await cache.get('case_2', now: DateTime.now().toUtc().add(const Duration(hours: 1))), isNull);
      expect(await cache.names(), isNot(contains('case_2')));
    });

    test('tampered entries are discarded', () async {
      await cache.put('case_3', {'a': 1}, expiresAt: DateTime.now().add(const Duration(hours: 1)));
      final f = File('${dir.path}/c/case_3.bin');
      final bytes = await f.readAsBytes();
      bytes[bytes.length - 1] ^= 0xFF;
      await f.writeAsBytes(bytes);
      expect(await cache.get('case_3'), isNull);
    });

    test('purgeAll removes files and the key', () async {
      await cache.put('case_4', {'a': 1}, expiresAt: DateTime.now().add(const Duration(hours: 1)));
      await cache.purgeAll();
      expect(await cache.names(), isEmpty);
      expect(keys.values.containsKey('aic.cache_key'), isFalse);
    });

    test('entry names cannot escape the cache directory', () {
      expect(() => cache.put('../evil', {}, expiresAt: DateTime.now()), throwsArgumentError);
    });
  });

  group('AppConfig', () {
    AppConfig cfg(String url, {bool dev = false}) => AppConfig(
        apiBaseUrl: url, institutionName: 'X', countryCode: 'XX', accentColor: const Color(0xFF000000),
        mapTileUrl: '', allowInsecureHttpForDev: dev);

    test('HTTPS is mandatory', () {
      expect(() => cfg('http://api.example/api/v1').validate(), throwsStateError);
      cfg('https://api.example/api/v1').validate();
    });

    test('plain HTTP only with the dev flag on loopback', () {
      cfg('http://10.0.2.2:8000/api/v1', dev: true).validate();
      expect(() => cfg('http://192.0.2.1/api/v1', dev: true).validate(), throwsStateError);
    });
  });

  group('ApiClient and AuthController', () {
    test('login requires MFA, then loads profile and markings', () async {
      final h = Harness.create()..stubLogin();
      await h.auth.start();
      expect(h.auth.stage, AuthStage.signedOut);
      await h.auth.login('analyste.test', 'pw');
      expect(h.auth.stage, AuthStage.mfa);
      expect(h.store.values.containsKey('aic.refresh_token'), isFalse);
      await h.auth.verifyMfa('123456');
      expect(h.auth.stage, AuthStage.ready);
      expect(h.auth.me!.can('case:read'), isTrue);
      expect(h.auth.markings[1], contains('RESTRICTED'));
    });

    test('server error codes are surfaced, never raw bodies', () async {
      final h = Harness.create();
      h.backend.on('POST /auth/login', {'code': 'invalid_credentials'}, status: 401);
      await h.auth.login('x', 'y');
      expect(h.auth.lastError, 'invalid_credentials');
      expect(h.auth.stage, isNot(AuthStage.mfa));
    });

    test('401 triggers one refresh then retries', () async {
      final h = Harness.create()..stubLogin();
      await h.auth.login('a', 'b');
      await h.auth.verifyMfa('123456');
      var first = true;
      h.backend.routes['GET /cases'] = (_) {
        if (first) {
          first = false;
          return http.Response('{"code":"invalid_token"}', 401);
        }
        return http.Response('[]', 200);
      };
      h.backend.on('POST /auth/refresh', {'access_token': 'access-2', 'refresh_token': 'sid.refresh-2', 'expires_at': 0, 'session_id': 'sid'});
      expect(await h.services.api.get('/cases'), isEmpty);
      expect(h.store.values['aic.refresh_token'], 'sid.refresh-2');
    });

    test('failed refresh signs out and wipes local data', () async {
      final h = Harness.create()..stubLogin();
      await h.auth.login('a', 'b');
      await h.auth.verifyMfa('123456');
      await h.services.offline.cache.put('case_x', {'a': 1}, expiresAt: DateTime.now().add(const Duration(hours: 1)));
      h.backend.on('GET /cases', {'code': 'session_invalid'}, status: 401);
      h.backend.on('POST /auth/refresh', {'code': 'invalid_refresh_token'}, status: 401);
      await expectLater(h.services.api.get('/cases'), throwsA(isA<ApiException>()));
      await Future<void>.delayed(const Duration(milliseconds: 100));
      expect(h.auth.stage, AuthStage.signedOut);
      expect(h.store.values.containsKey('aic.refresh_token'), isFalse);
      expect(await h.services.offline.cache.names(), isEmpty);
    });

    test('remote wipe order purges the device', () async {
      final h = Harness.create()..stubLogin();
      h.backend.on('GET /me/devices/current/status', {'status': 'lost', 'wipe_requested': true});
      await h.auth.login('a', 'b');
      await h.auth.verifyMfa('123456');
      expect(h.auth.stage, AuthStage.signedOut);
      expect(h.auth.lastError, 'device_revoked');
    });

    test('stored session reopens only after local biometric success', () async {
      final h = Harness.create(biometric: FakeBiometric(succeeds: false))..stubLogin();
      await h.store.write('aic.refresh_token', 'sid.r');
      await h.auth.start();
      expect(h.auth.stage, AuthStage.locked);
      await h.auth.unlockWithBiometrics('reason');
      expect(h.auth.stage, AuthStage.locked);
      h.biometric.succeeds = true;
      await h.auth.unlockWithBiometrics('reason');
      expect(h.auth.stage, AuthStage.ready);
    });

    test('without biometrics the stored session is discarded', () async {
      final h = Harness.create(biometric: FakeBiometric(isAvailable: false));
      await h.store.write('aic.refresh_token', 'sid.r');
      await h.auth.start();
      await h.auth.unlockWithBiometrics('reason');
      expect(h.auth.stage, AuthStage.signedOut);
      expect(h.store.values.containsKey('aic.refresh_token'), isFalse);
    });

    test('backgrounded session locks after the timeout', () async {
      final h = Harness.create()..stubLogin();
      await h.auth.login('a', 'b');
      await h.auth.verifyMfa('123456');
      h.auth.onBackground();
      // Simulate a long absence.
      final auth = AuthController(api: h.auth.api, tokens: h.auth.tokens, device: h.auth.device,
          biometric: h.biometric, cache: h.auth.cache, lockAfter: Duration.zero)
        ..stage = AuthStage.ready;
      auth.onBackground();
      await Future<void>.delayed(const Duration(milliseconds: 5));
      auth.onForeground();
      expect(auth.stage, AuthStage.locked);
    });
  });

  group('OfflineService', () {
    test('only server-accepted operation types can be queued', () async {
      final h = Harness.create();
      expect(() => h.services.offline.enqueue('delete_case', 'c1', {}), throwsArgumentError);
      await h.services.offline.enqueue('add_statement', 'c1', {'kind': 'claim', 'text': 'x'});
      expect((await h.services.offline.pending()).single['op_type'], 'add_statement');
    });

    test('grants not listed by the server are purged', () async {
      final h = Harness.create();
      final cache = h.services.offline.cache;
      final exp = DateTime.now().add(const Duration(hours: 1));
      await cache.put('case_aaa', {'x': 1}, expiresAt: exp);
      await cache.put('case_bbb', {'x': 1}, expiresAt: exp);
      h.backend.on('GET /sync/grants', [
        {'case_id': 'aaa', 'grant_id': 'g', 'expires_at': exp.toIso8601String()},
      ]);
      await h.services.offline.reconcileGrants();
      expect(await cache.names(), ['case_aaa']);
    });
  });
}
