import 'package:flutter/widgets.dart';

import 'api/api_client.dart';
import 'auth/auth_controller.dart';
import 'config.dart';
import 'offline/offline_service.dart';

/// Dependency container exposed to the widget tree.
class AppServices extends InheritedWidget {
  const AppServices({
    super.key,
    required this.config,
    required this.api,
    required this.auth,
    required this.offline,
    required this.locale,
    required super.child,
  });

  final AppConfig config;
  final ApiClient api;
  final AuthController auth;
  final OfflineService offline;

  /// Selected interface language; null follows the device language.
  final ValueNotifier<Locale?> locale;

  static AppServices of(BuildContext context) {
    final s = context.dependOnInheritedWidgetOfExactType<AppServices>();
    assert(s != null, 'AppServices missing from the widget tree');
    return s!;
  }

  @override
  bool updateShouldNotify(AppServices oldWidget) => false;
}
