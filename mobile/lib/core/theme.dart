import 'package:flutter/cupertino.dart';
import 'package:flutter/material.dart';

/// Institutional palette: anthracite background, night blue surfaces,
/// silver text accents and a restrained electric blue.
class AicColors {
  static const anthracite = Color(0xFF15181D);
  static const surface = Color(0xFF1C222B);
  static const nightBlue = Color(0xFF14233B);
  static const outline = Color(0xFF2E3846);
  static const silver = Color(0xFFC9CED6);
  static const silverMuted = Color(0xFF8D96A3);
  static const danger = Color(0xFFE5484D);
  static const warning = Color(0xFFE2A336);
  static const success = Color(0xFF3FB27F);
}

ThemeData buildTheme(Color accent) {
  final scheme = ColorScheme.fromSeed(
    seedColor: accent,
    brightness: Brightness.dark,
  ).copyWith(
    primary: accent,
    surface: AicColors.surface,
    onSurface: AicColors.silver,
    surfaceContainerHighest: AicColors.nightBlue,
    outline: AicColors.outline,
    error: AicColors.danger,
  );
  const text = TextTheme(
    headlineSmall: TextStyle(fontSize: 22, fontWeight: FontWeight.w600, letterSpacing: 0.2),
    titleLarge: TextStyle(fontSize: 18, fontWeight: FontWeight.w600),
    titleMedium: TextStyle(fontSize: 16, fontWeight: FontWeight.w600),
    bodyLarge: TextStyle(fontSize: 16, height: 1.4),
    bodyMedium: TextStyle(fontSize: 14, height: 1.4),
    labelSmall: TextStyle(fontSize: 11, letterSpacing: 0.8, fontWeight: FontWeight.w600),
  );
  return ThemeData(
    useMaterial3: true,
    colorScheme: scheme,
    scaffoldBackgroundColor: AicColors.anthracite,
    textTheme: text.apply(bodyColor: AicColors.silver, displayColor: AicColors.silver),
    appBarTheme: const AppBarTheme(
      backgroundColor: AicColors.anthracite,
      foregroundColor: AicColors.silver,
      elevation: 0,
      centerTitle: false,
    ),
    cardTheme: CardThemeData(
      color: AicColors.surface,
      elevation: 0,
      margin: const EdgeInsets.symmetric(vertical: 6),
      shape: RoundedRectangleBorder(
        borderRadius: BorderRadius.circular(10),
        side: const BorderSide(color: AicColors.outline),
      ),
    ),
    inputDecorationTheme: InputDecorationTheme(
      filled: true,
      fillColor: AicColors.nightBlue,
      border: OutlineInputBorder(borderRadius: BorderRadius.circular(8), borderSide: BorderSide.none),
      labelStyle: const TextStyle(color: AicColors.silverMuted),
    ),
    navigationBarTheme: const NavigationBarThemeData(
      backgroundColor: AicColors.surface,
      indicatorColor: AicColors.nightBlue,
    ),
    dividerTheme: const DividerThemeData(color: AicColors.outline, space: 1),
    pageTransitionsTheme: const PageTransitionsTheme(builders: {
      TargetPlatform.android: FadeForwardsPageTransitionsBuilder(),
      TargetPlatform.iOS: CupertinoPageTransitionsBuilder(),
    }),
  );
}
