import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import '../../core/auth/auth_controller.dart';
import '../../core/services.dart';
import '../../core/theme.dart';
import '../../l10n/app_localizations.dart';
import '../../widgets/common.dart';

class Brand extends StatelessWidget {
  const Brand({super.key});

  @override
  Widget build(BuildContext context) {
    final cfg = AppServices.of(context).config;
    return Column(children: [
      Container(
        width: 56,
        height: 56,
        decoration: BoxDecoration(
          border: Border.all(color: AicColors.silver, width: 1.5),
          borderRadius: BorderRadius.circular(12),
        ),
        alignment: Alignment.center,
        child: const Text('AIC', style: TextStyle(fontWeight: FontWeight.w700, letterSpacing: 2)),
      ),
      const SizedBox(height: 16),
      Text(cfg.institutionName, textAlign: TextAlign.center,
          style: Theme.of(context).textTheme.titleMedium?.copyWith(letterSpacing: 2)),
    ]);
  }
}

/// Secure start-up: decides between sign-in, local unlock and the workspace.
class SplashScreen extends StatelessWidget {
  const SplashScreen({super.key});

  @override
  Widget build(BuildContext context) {
    final t = AppLocalizations.of(context);
    return Scaffold(
      body: Center(
        child: Column(mainAxisSize: MainAxisSize.min, children: [
          const Brand(),
          const SizedBox(height: 32),
          const SizedBox(width: 22, height: 22, child: CircularProgressIndicator(strokeWidth: 2)),
          const SizedBox(height: 12),
          Text(t.checkingIntegrity, style: const TextStyle(color: AicColors.silverMuted)),
        ]),
      ),
    );
  }
}

class LoginScreen extends StatefulWidget {
  const LoginScreen({super.key});

  @override
  State<LoginScreen> createState() => _LoginScreenState();
}

class _LoginScreenState extends State<LoginScreen> {
  final _user = TextEditingController();
  final _pass = TextEditingController();
  bool _busy = false;

  @override
  void dispose() {
    _user.dispose();
    _pass.dispose();
    super.dispose();
  }

  Future<void> _submit(AuthController auth) async {
    if (_user.text.trim().isEmpty || _pass.text.isEmpty) return;
    setState(() => _busy = true);
    await auth.login(_user.text.trim(), _pass.text);
    _pass.clear();
    if (mounted) setState(() => _busy = false);
  }

  @override
  Widget build(BuildContext context) {
    final t = AppLocalizations.of(context);
    final auth = AppServices.of(context).auth;
    return Scaffold(
      body: SafeArea(
        child: Center(
          child: SingleChildScrollView(
            padding: const EdgeInsets.all(24),
            child: ConstrainedBox(
              constraints: const BoxConstraints(maxWidth: 420),
              child: AutofillGroup(
                child: Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
                  const Brand(),
                  const SizedBox(height: 32),
                  Text(t.signInTitle, style: Theme.of(context).textTheme.headlineSmall),
                  const SizedBox(height: 4),
                  Text(t.signInSubtitle, style: const TextStyle(color: AicColors.silverMuted)),
                  const SizedBox(height: 24),
                  if (auth.deviceRiskSignal) NoticeBox(t.deviceRiskWarning),
                  if (auth.lastError != null) NoticeBox(_loginError(t, auth.lastError!)),
                  TextField(
                    key: const Key('username'),
                    controller: _user,
                    autocorrect: false,
                    enableSuggestions: false,
                    autofillHints: const [AutofillHints.username],
                    decoration: InputDecoration(labelText: t.username),
                  ),
                  const SizedBox(height: 12),
                  TextField(
                    key: const Key('password'),
                    controller: _pass,
                    obscureText: true,
                    autocorrect: false,
                    enableSuggestions: false,
                    autofillHints: const [AutofillHints.password],
                    onSubmitted: (_) => _submit(auth),
                    decoration: InputDecoration(labelText: t.password),
                  ),
                  const SizedBox(height: 20),
                  FilledButton(
                    key: const Key('signIn'),
                    onPressed: _busy ? null : () => _submit(auth),
                    child: Padding(
                      padding: const EdgeInsets.symmetric(vertical: 12),
                      child: Text(_busy ? t.signingIn : t.signIn),
                    ),
                  ),
                  const SizedBox(height: 16),
                  Text(t.recoveryHint, textAlign: TextAlign.center,
                      style: const TextStyle(fontSize: 12, color: AicColors.silverMuted)),
                ]),
              ),
            ),
          ),
        ),
      ),
    );
  }

  String _loginError(AppLocalizations t, String code) {
    switch (code) {
      case 'invalid_credentials':
        return t.loginFailed;
      case 'rate_limited':
        return t.errorRateLimited;
      case 'network_unavailable':
        return t.errorNetwork;
      case 'session_expired':
        return t.sessionExpired;
      case 'device_revoked':
        return t.deviceRevokedNotice;
      default:
        return t.errorGeneric;
    }
  }
}

class MfaScreen extends StatefulWidget {
  const MfaScreen({super.key});

  @override
  State<MfaScreen> createState() => _MfaScreenState();
}

class _MfaScreenState extends State<MfaScreen> {
  final _code = TextEditingController();
  bool _busy = false;

  @override
  void dispose() {
    _code.dispose();
    super.dispose();
  }

  String? _secret(String? uri) => uri == null ? null : Uri.parse(uri).queryParameters['secret'];

  @override
  Widget build(BuildContext context) {
    final t = AppLocalizations.of(context);
    final auth = AppServices.of(context).auth;
    final secret = _secret(auth.enrollmentUri);
    return Scaffold(
      appBar: AppBar(title: Text(secret != null ? t.mfaEnrollTitle : t.mfaTitle)),
      body: SafeArea(
        child: ListView(padding: const EdgeInsets.all(24), children: [
          if (secret != null) ...[
            Text(t.mfaEnrollPrompt),
            const SizedBox(height: 12),
            Card(
              child: ListTile(
                title: Text(t.mfaSecretLabel),
                subtitle: SelectableText(secret, style: const TextStyle(fontFamily: 'monospace', letterSpacing: 1.5)),
                trailing: IconButton(
                  tooltip: t.copy,
                  icon: const Icon(Icons.copy),
                  onPressed: () => Clipboard.setData(ClipboardData(text: secret)),
                ),
              ),
            ),
            const SizedBox(height: 12),
          ],
          Text(t.mfaPrompt),
          const SizedBox(height: 16),
          if (auth.lastError != null) NoticeBox(t.mfaFailed),
          TextField(
            key: const Key('mfaCode'),
            controller: _code,
            keyboardType: TextInputType.number,
            maxLength: 6,
            autofillHints: const [AutofillHints.oneTimeCode],
            inputFormatters: [FilteringTextInputFormatter.digitsOnly],
            decoration: InputDecoration(labelText: t.mfaCode),
          ),
          const SizedBox(height: 12),
          FilledButton(
            onPressed: _busy
                ? null
                : () async {
                    setState(() => _busy = true);
                    await auth.verifyMfa(_code.text);
                    _code.clear();
                    if (mounted) setState(() => _busy = false);
                  },
            child: Text(t.verify),
          ),
          TextButton(onPressed: auth.logout, child: Text(t.cancel)),
        ]),
      ),
    );
  }
}

class LockScreen extends StatelessWidget {
  const LockScreen({super.key});

  @override
  Widget build(BuildContext context) {
    final t = AppLocalizations.of(context);
    final auth = AppServices.of(context).auth;
    return Scaffold(
      body: Center(
        child: Padding(
          padding: const EdgeInsets.all(24),
          child: Column(mainAxisSize: MainAxisSize.min, children: [
            const Brand(),
            const SizedBox(height: 32),
            const Icon(Icons.lock_outline, size: 36, color: AicColors.silverMuted),
            const SizedBox(height: 8),
            Text(t.locked, style: Theme.of(context).textTheme.titleMedium),
            const SizedBox(height: 4),
            Text(t.biometricExplanation, textAlign: TextAlign.center,
                style: const TextStyle(color: AicColors.silverMuted, fontSize: 12)),
            if (auth.lastError != null) NoticeBox(t.biometricFailed),
            const SizedBox(height: 20),
            FilledButton.icon(
              icon: const Icon(Icons.fingerprint),
              onPressed: () => auth.unlockWithBiometrics(t.biometricReason),
              label: Text(t.biometricUnlock),
            ),
            TextButton(onPressed: auth.logout, child: Text(t.signOutAndSignIn)),
          ]),
        ),
      ),
    );
  }
}
