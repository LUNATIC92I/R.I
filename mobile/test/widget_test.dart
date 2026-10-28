import 'package:aic_mobile/core/auth/auth_controller.dart';
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';

import 'helpers.dart';

void main() {
  testWidgets('login screen is available in French and English', (tester) async {
    final h = Harness.create();
    await h.auth.start();
    await tester.pumpWidget(h.app());
    await tester.pumpAndSettle();
    expect(find.text('Se connecter'), findsOneWidget);
    expect(find.text('Identifiant'), findsOneWidget);
    h.services.locale.value = const Locale('en');
    await tester.pumpAndSettle();
    expect(find.text('Sign in'), findsOneWidget);
    expect(find.text('Username'), findsOneWidget);
  });

  testWidgets('full sign-in flow reaches the dashboard', (tester) async {
    final h = Harness.create()..stubLogin();
    await h.auth.start();
    await tester.pumpWidget(h.app());
    await tester.pumpAndSettle();
    await tester.enterText(find.byKey(const Key('username')), 'analyste.test');
    await tester.enterText(find.byKey(const Key('password')), 'synthetic');
    await tester.tap(find.byKey(const Key('signIn')));
    await tester.pumpAndSettle();
    expect(find.text('Vérification multifacteur'), findsOneWidget);
    await tester.enterText(find.byKey(const Key('mfaCode')), '123456');
    await tester.tap(find.text('Vérifier'));
    await tester.pumpAndSettle();
    expect(h.auth.stage, AuthStage.ready);
    expect(find.text('Tableau de bord'), findsWidgets);
    expect(find.text('Dossiers actifs accessibles'), findsOneWidget);
    expect(find.textContaining('Indicateurs limités'), findsOneWidget);
  });

  testWidgets('content is hidden when the app leaves the foreground', (tester) async {
    final h = Harness.create();
    await h.auth.start();
    await tester.pumpWidget(h.app());
    await tester.pumpAndSettle();
    expect(find.byIcon(Icons.shield_outlined), findsNothing);
    tester.binding.handleAppLifecycleStateChanged(AppLifecycleState.inactive);
    await tester.pump();
    expect(find.byIcon(Icons.shield_outlined), findsOneWidget);
    tester.binding.handleAppLifecycleStateChanged(AppLifecycleState.resumed);
    await tester.pump();
    expect(find.byIcon(Icons.shield_outlined), findsNothing);
  });

  testWidgets('lock screen offers biometric unlock', (tester) async {
    final h = Harness.create()..stubLogin();
    await h.store.write('aic.refresh_token', 'sid.r');
    await h.auth.start();
    await tester.pumpWidget(h.app());
    await tester.pumpAndSettle();
    expect(find.text('Session verrouillée'), findsOneWidget);
    await tester.tap(find.text('Déverrouiller'));
    await tester.pumpAndSettle();
    expect(h.biometric.calls, 1);
    expect(h.auth.stage, AuthStage.ready);
  });

  testWidgets('error and empty states are explicit', (tester) async {
    final h = Harness.create()..stubLogin();
    h.backend.on('GET /dashboard', {'code': 'internal_error'}, status: 500);
    await h.auth.start();
    await h.auth.login('a', 'b');
    await h.auth.verifyMfa('123456');
    await tester.pumpWidget(h.app());
    await tester.pumpAndSettle();
    expect(find.text('Une erreur est survenue.'), findsOneWidget);
    expect(find.text('Réessayer'), findsOneWidget);
    await tester.tap(find.text('Alertes').last);
    await tester.pumpAndSettle();
    expect(find.text('Aucune alerte'), findsOneWidget);
  });
}
