import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import '../auth/auth_controller.dart';
import '../theme.dart';

/// Hides all content whenever the app is not in the foreground, so the
/// recent-apps preview never shows sensitive data, and enables FLAG_SECURE
/// on Android (no screenshots, no screen recording, blank thumbnail).
class PrivacyGuard extends StatefulWidget {
  const PrivacyGuard({super.key, required this.auth, required this.child});

  final AuthController auth;
  final Widget child;

  static const channel = MethodChannel('aic/secure_screen');

  @override
  State<PrivacyGuard> createState() => _PrivacyGuardState();
}

class _PrivacyGuardState extends State<PrivacyGuard> with WidgetsBindingObserver {
  bool _obscured = false;

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addObserver(this);
    PrivacyGuard.channel.invokeMethod<void>('enable').catchError((_) {});
  }

  @override
  void dispose() {
    WidgetsBinding.instance.removeObserver(this);
    super.dispose();
  }

  @override
  void didChangeAppLifecycleState(AppLifecycleState state) {
    final hidden = state != AppLifecycleState.resumed;
    if (hidden != _obscured) setState(() => _obscured = hidden);
    if (state == AppLifecycleState.paused) widget.auth.onBackground();
    if (state == AppLifecycleState.resumed) widget.auth.onForeground();
  }

  @override
  Widget build(BuildContext context) {
    return Stack(
      textDirection: TextDirection.ltr,
      children: [
        widget.child,
        if (_obscured)
          const Positioned.fill(
            child: ColoredBox(
              color: AicColors.anthracite,
              child: Center(child: Icon(Icons.shield_outlined, size: 48, color: AicColors.silverMuted)),
            ),
          ),
      ],
    );
  }
}
