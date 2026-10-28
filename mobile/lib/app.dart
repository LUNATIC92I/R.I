import 'package:flutter/material.dart';
import 'package:flutter_localizations/flutter_localizations.dart';

import 'core/auth/auth_controller.dart';
import 'core/security/privacy_guard.dart';
import 'core/services.dart';
import 'core/theme.dart';
import 'features/auth/auth_screens.dart';
import 'features/home/home_shell.dart';
import 'l10n/app_localizations.dart';

class AicApp extends StatelessWidget {
  const AicApp({super.key, required this.services});

  final AppServices services;

  @override
  Widget build(BuildContext context) {
    return AppServices(
      config: services.config,
      api: services.api,
      auth: services.auth,
      offline: services.offline,
      locale: services.locale,
      child: ValueListenableBuilder<Locale?>(
        valueListenable: services.locale,
        builder: (context, locale, _) => MaterialApp(
          title: services.config.institutionName,
          debugShowCheckedModeBanner: false,
          theme: buildTheme(services.config.accentColor),
          locale: locale,
          supportedLocales: AppLocalizations.supportedLocales,
          localizationsDelegates: const [
            AppLocalizations.delegate,
            GlobalMaterialLocalizations.delegate,
            GlobalWidgetsLocalizations.delegate,
            GlobalCupertinoLocalizations.delegate,
          ],
          builder: (context, child) => PrivacyGuard(auth: services.auth, child: child!),
          home: ListenableBuilder(
            listenable: services.auth,
            builder: (context, _) => switch (services.auth.stage) {
              AuthStage.starting => const SplashScreen(),
              AuthStage.signedOut => const LoginScreen(),
              AuthStage.mfa => const MfaScreen(),
              AuthStage.locked => const LockScreen(),
              AuthStage.ready => const HomeShell(),
            },
          ),
        ),
      ),
    );
  }
}
