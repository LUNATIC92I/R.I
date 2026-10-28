# Compilation Android et préparation iOS

## Prérequis

- Flutter 3.47.x stable (testé : 3.47.8, Dart 3.13.7)
- Android : SDK (plateformes 35/36, build-tools), JDK 17+, NDK installé automatiquement par Gradle
- iOS : macOS avec Xcode récent, CocoaPods, compte Apple Developer de l'institution (non disponible dans l'environnement de développement de ce dépôt)

## Paramètres de compilation

| `--dart-define` | Rôle | Défaut |
|---|---|---|
| `AIC_API_BASE_URL` | URL HTTPS de l'API (`.../api/v1`) | `https://api.aic.invalid/api/v1` (volontairement non résoluble) |
| `AIC_INSTITUTION` | Nom affiché | `AFRICAN INTELLIGENCE CORE` |
| `AIC_COUNTRY` | Code pays ISO des nouveaux dossiers | `XX` |
| `AIC_ACCENT` | Couleur d'accent `RRGGBB` | `2F7DF6` |
| `AIC_MAP_TILES` | Modèle d'URL du serveur de tuiles institutionnel | vide (aucune tuile chargée) |
| `AIC_DEV_ALLOW_HTTP` | Autorise `http://` vers le bouclage (debug uniquement) | `false` |

Aucun secret n'est compilé dans l'application.

## Vérifications

```bash
cd mobile && flutter pub get && flutter gen-l10n
```

```bash
flutter analyze && flutter test
```

## Android

APK de test (signé avec la clé de debug si `android/key.properties` est absent : **usage interne uniquement**) :

```bash
flutter build apk --release --dart-define=AIC_API_BASE_URL=https://api.preprod.institution.example/api/v1
```

Android App Bundle pour distribution (exige la clé de l'institution) :

```bash
flutter build appbundle --release --dart-define=AIC_API_BASE_URL=https://api.institution.example/api/v1
```

Signature : créer `mobile/android/key.properties` (jamais versionné, ignoré par `.gitignore`) :

```properties
storeFile=/chemin/protégé/aic-release.jks
storePassword=...
keyAlias=aic
keyPassword=...
```

Mesures intégrées : `FLAG_SECURE`, `allowBackup=false` et règles d'extraction excluant toutes les données, trafic en clair interdit (sauf bouclage en debug), autorités de certification système uniquement, `minSdk` 24, minification R8 en release, `FlutterFragmentActivity` pour BiometricPrompt.

Épinglage de certificats : ajouter un `<pin-set>` dans `android/app/src/main/res/xml/network_security_config.xml` avec l'empreinte SPKI du certificat de l'API et une empreinte de secours.

## iOS (préparation)

La compilation iOS nécessite macOS et Xcode ; elle **n'a pas été effectuée** dans l'environnement Linux de développement.

1. `cd mobile/ios && pod install`
2. Ouvrir `Runner.xcworkspace`, définir l'équipe de signature de l'institution et l'identifiant de bundle (`org.aic.core.aicMobile` par défaut, à remplacer).
3. Vérifier `Info.plist` : `NSFaceIDUsageDescription` (présent), ATS sans exception (présent), partage de fichiers désactivé (présent).
4. Capacités : aucune capacité de notification tant que le connecteur APNs n'est pas configuré côté serveur ; Keychain Sharing non requis.
5. Compiler : `flutter build ipa --release --dart-define=AIC_API_BASE_URL=...`
6. Distribution autorisée : Apple Business Manager / programme Enterprise de l'institution, ou TestFlight **interne** ; jamais l'App Store public. Déployer via le MDM institutionnel avec politique de code d'accès obligatoire.

Le masquage du contenu dans le sélecteur d'applications est assuré par l'application (couche opaque lorsque l'état n'est plus `resumed`) ; iOS ne permet pas de bloquer les captures d'écran, seule leur détection est possible (non implémentée).
