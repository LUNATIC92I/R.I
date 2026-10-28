import 'package:flutter/foundation.dart';

import '../../models/models.dart';
import '../api/api_client.dart';
import '../offline/encrypted_cache.dart';
import '../security/device_identity.dart';
import 'biometric_gate.dart';
import 'token_store.dart';

enum AuthStage { starting, signedOut, mfa, locked, ready }

class AuthController extends ChangeNotifier {
  AuthController({
    required this.api,
    required this.tokens,
    required this.device,
    required this.biometric,
    required this.cache,
    this.lockAfter = const Duration(minutes: 2),
  }) {
    api.onSessionExpired = () => _signOutLocally('session_expired');
  }

  final ApiClient api;
  final TokenStore tokens;
  final DeviceIdentity device;
  final BiometricGate biometric;
  final EncryptedCache cache;
  final Duration lockAfter;

  AuthStage stage = AuthStage.starting;
  Me? me;
  String? mfaToken;
  String? enrollmentUri;
  String? lastError;
  bool deviceRiskSignal = false;

  /// Institution-defined classification markings, by rank.
  Map<int, String> markings = {};
  DateTime? _backgroundedAt;

  Future<void> start() async {
    deviceRiskSignal = device.integritySignals()['heuristic_root_or_jailbreak'] == true;
    stage = await tokens.hasSession() ? AuthStage.locked : AuthStage.signedOut;
    notifyListeners();
  }

  Future<void> login(String username, String password) async {
    lastError = null;
    try {
      final resp = Map<String, dynamic>.from(await api.postPublic('/auth/login', {
        'username': username,
        'password': password,
        'device': await _device(),
      }) as Map);
      mfaToken = resp['mfa_token'] as String;
      enrollmentUri = resp['totp_provisioning_uri'] as String?;
      stage = AuthStage.mfa;
    } on ApiException catch (e) {
      lastError = e.code;
    }
    notifyListeners();
  }

  Future<Map<String, Object>> _device() async => {
        'install_id': await device.installId(),
        'platform': device.platform,
        'label': 'AIC ${device.platform}',
        'integrity': device.integritySignals(),
      };

  Future<void> verifyMfa(String code) async {
    lastError = null;
    try {
      final tok = Map<String, dynamic>.from(
          await api.postPublic('/auth/mfa', {'mfa_token': mfaToken, 'code': code}) as Map);
      await tokens.saveFromJson(tok);
      mfaToken = null;
      enrollmentUri = null;
      await _loadMe();
    } on ApiException catch (e) {
      lastError = e.code;
      if (e.code == 'invalid_mfa_challenge') stage = AuthStage.signedOut;
    }
    notifyListeners();
  }

  Future<void> unlockWithBiometrics(String reason) async {
    lastError = null;
    if (!await biometric.available()) {
      // Without a local factor the stored session cannot be reopened safely.
      await _signOutLocally('biometrics_unavailable');
      return;
    }
    if (!await biometric.authenticate(reason)) {
      lastError = 'biometric_failed';
      notifyListeners();
      return;
    }
    try {
      await _loadMe();
    } on ApiException catch (e) {
      lastError = e.code;
      if (e.status == 401) await _signOutLocally(e.code);
    }
    notifyListeners();
  }

  Future<void> _loadMe() async {
    me = Me(Map<String, dynamic>.from(await api.get('/me') as Map));
    final levels = (await api.get('/admin/classifications') as List).cast<Map>();
    markings = {for (final l in levels) l['rank'] as int: l['marking'] as String};
    stage = AuthStage.ready;
    await checkDeviceStatus();
  }

  /// Applies a remote revocation or wipe order as soon as it is seen.
  Future<void> checkDeviceStatus() async {
    try {
      final status = Map<String, dynamic>.from(await api.get('/me/devices/current/status') as Map);
      if (status['wipe_requested'] == true || (status['status'] != 'active' && status['status'] != 'none')) {
        await _signOutLocally('device_revoked');
      }
    } on ApiException catch (e) {
      if (e.status == 401) await _signOutLocally('device_revoked');
    }
  }

  Future<void> stepUp(String password, String code) async {
    await api.post('/auth/step-up', body: {'password': password, 'code': code});
  }

  Future<void> logout() async {
    try {
      await api.post('/auth/logout');
    } on ApiException {
      // Local data is wiped even if the server cannot be reached.
    }
    await _signOutLocally('logout');
  }

  Future<void> _signOutLocally(String reason) async {
    // Hide the workspace first, then erase credentials and local data.
    me = null;
    stage = AuthStage.signedOut;
    lastError = reason == 'logout' ? null : reason;
    notifyListeners();
    await tokens.clear();
    await cache.purgeAll();
  }

  void onBackground() => _backgroundedAt = DateTime.now();

  void onForeground() {
    final since = _backgroundedAt;
    _backgroundedAt = null;
    if (stage == AuthStage.ready && since != null && DateTime.now().difference(since) > lockAfter) {
      stage = AuthStage.locked;
      notifyListeners();
    } else if (stage == AuthStage.ready) {
      checkDeviceStatus();
    }
  }
}
