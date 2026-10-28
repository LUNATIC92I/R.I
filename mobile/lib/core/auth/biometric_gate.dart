import 'package:local_auth/local_auth.dart';

/// Local biometric unlock. The OS performs the match; no biometric data ever
/// reaches the application or the server. It only unlocks a session that
/// already exists on this device.
abstract class BiometricGate {
  Future<bool> available();
  Future<bool> authenticate(String reason);
}

class LocalBiometricGate implements BiometricGate {
  final _auth = LocalAuthentication();

  @override
  Future<bool> available() async {
    try {
      return await _auth.canCheckBiometrics && await _auth.isDeviceSupported();
    } on Exception {
      return false;
    }
  }

  @override
  Future<bool> authenticate(String reason) async {
    try {
      return await _auth.authenticate(localizedReason: reason, biometricOnly: true);
    } on Exception {
      return false;
    }
  }
}
