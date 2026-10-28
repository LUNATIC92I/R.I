import 'package:flutter/material.dart';

import '../core/api/api_client.dart';
import '../core/services.dart';
import '../core/theme.dart';
import '../l10n/app_localizations.dart';

/// Maps a server error code to a user-facing message.
String errorMessage(BuildContext context, Object error) {
  final t = AppLocalizations.of(context);
  if (error is ApiException) {
    if (error.isNetwork) return t.errorNetwork;
    if (error.stepUpRequired) return t.errorStepUp;
    switch (error.status) {
      case 403:
        return t.errorForbidden;
      case 404:
        return t.errorNotFound;
      case 409:
        return t.errorConflict;
      case 422:
      case 400:
        return t.errorValidation(error.code);
      case 429:
        return t.errorRateLimited;
    }
  }
  return t.errorGeneric;
}

/// Loading, empty, error and data states for any asynchronous view.
class AsyncView<T> extends StatefulWidget {
  const AsyncView({super.key, required this.load, required this.builder, this.isEmpty, this.emptyText});

  final Future<T> Function() load;
  final Widget Function(BuildContext context, T data, VoidCallback reload) builder;
  final bool Function(T data)? isEmpty;
  final String? emptyText;

  @override
  State<AsyncView<T>> createState() => _AsyncViewState<T>();
}

class _AsyncViewState<T> extends State<AsyncView<T>> {
  late Future<T> _future;

  @override
  void initState() {
    super.initState();
    _future = widget.load();
  }

  void _reload() => setState(() => _future = widget.load());

  @override
  Widget build(BuildContext context) {
    final t = AppLocalizations.of(context);
    return FutureBuilder<T>(
      future: _future,
      builder: (context, snap) {
        if (snap.connectionState != ConnectionState.done) {
          return Center(
            child: Semantics(label: t.loading, child: const CircularProgressIndicator(strokeWidth: 2)),
          );
        }
        if (snap.hasError) {
          return MessageState(
            icon: Icons.error_outline,
            text: errorMessage(context, snap.error!),
            action: TextButton(onPressed: _reload, child: Text(t.retry)),
          );
        }
        final data = snap.data as T;
        if (widget.isEmpty?.call(data) ?? false) {
          return MessageState(
            icon: Icons.inbox_outlined,
            text: widget.emptyText ?? t.emptyList,
            action: TextButton(onPressed: _reload, child: Text(t.refresh)),
          );
        }
        return RefreshIndicator(
          onRefresh: () async => _reload(),
          child: widget.builder(context, data, _reload),
        );
      },
    );
  }
}

class MessageState extends StatelessWidget {
  const MessageState({super.key, required this.icon, required this.text, this.action});

  final IconData icon;
  final String text;
  final Widget? action;

  @override
  Widget build(BuildContext context) {
    return Center(
      child: Padding(
        padding: const EdgeInsets.all(32),
        child: Column(mainAxisSize: MainAxisSize.min, children: [
          Icon(icon, size: 40, color: AicColors.silverMuted),
          const SizedBox(height: 12),
          Text(text, textAlign: TextAlign.center, style: Theme.of(context).textTheme.bodyMedium),
          if (action != null) ...[const SizedBox(height: 8), action!],
        ]),
      ),
    );
  }
}

class SectionTitle extends StatelessWidget {
  const SectionTitle(this.text, {super.key});

  final String text;

  @override
  Widget build(BuildContext context) => Padding(
        padding: const EdgeInsets.fromLTRB(4, 16, 4, 6),
        child: Text(text.toUpperCase(),
            style: Theme.of(context).textTheme.labelSmall?.copyWith(color: AicColors.silverMuted)),
      );
}

class Tag extends StatelessWidget {
  const Tag(this.label, {super.key, this.color});

  final String label;
  final Color? color;

  @override
  Widget build(BuildContext context) {
    final c = color ?? AicColors.silverMuted;
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 3),
      decoration: BoxDecoration(
        border: Border.all(color: c.withValues(alpha: 0.6)),
        borderRadius: BorderRadius.circular(4),
      ),
      child: Text(label, style: TextStyle(fontSize: 11, color: c, fontWeight: FontWeight.w600)),
    );
  }
}

/// Classification marking shown at the top of every sensitive screen.
class ClassificationBanner extends StatelessWidget {
  const ClassificationBanner({super.key, required this.rank});

  final int rank;

  @override
  Widget build(BuildContext context) {
    final t = AppLocalizations.of(context);
    final label = AppServices.of(context).auth.markings[rank] ?? t.classificationLevel(rank);
    final color = rank >= 2 ? AicColors.danger : (rank == 1 ? AicColors.warning : AicColors.success);
    return Semantics(
      label: label,
      child: Container(
        width: double.infinity,
        color: color.withValues(alpha: 0.18),
        padding: const EdgeInsets.symmetric(vertical: 4),
        child: Text(label,
            textAlign: TextAlign.center, style: TextStyle(color: color, fontSize: 11, fontWeight: FontWeight.w700)),
      ),
    );
  }
}

class NoticeBox extends StatelessWidget {
  const NoticeBox(this.text, {super.key});

  final String text;

  @override
  Widget build(BuildContext context) => Container(
        margin: const EdgeInsets.symmetric(vertical: 8),
        padding: const EdgeInsets.all(12),
        decoration: BoxDecoration(
          color: AicColors.nightBlue,
          borderRadius: BorderRadius.circular(8),
          border: Border.all(color: AicColors.outline),
        ),
        child: Row(crossAxisAlignment: CrossAxisAlignment.start, children: [
          const Icon(Icons.info_outline, size: 18, color: AicColors.silverMuted),
          const SizedBox(width: 8),
          Expanded(child: Text(text, style: const TextStyle(fontSize: 12.5, color: AicColors.silver))),
        ]),
      );
}

Future<bool> confirm(BuildContext context, String title, String body) async {
  final t = AppLocalizations.of(context);
  final ok = await showDialog<bool>(
    context: context,
    builder: (c) => AlertDialog(
      title: Text(title),
      content: Text(body),
      actions: [
        TextButton(onPressed: () => Navigator.pop(c, false), child: Text(t.cancel)),
        FilledButton(onPressed: () => Navigator.pop(c, true), child: Text(t.confirm)),
      ],
    ),
  );
  return ok ?? false;
}

void toast(BuildContext context, String message) {
  ScaffoldMessenger.of(context)
    ..hideCurrentSnackBar()
    ..showSnackBar(SnackBar(content: Text(message), behavior: SnackBarBehavior.floating));
}

String fmtDate(DateTime? d) {
  if (d == null) return '…';
  String two(int v) => v.toString().padLeft(2, '0');
  return '${d.year}-${two(d.month)}-${two(d.day)} ${two(d.hour)}:${two(d.minute)}';
}

String fmtDay(DateTime? d) => d == null ? '…' : fmtDate(d).substring(0, 10);


/// Runs [action]; if the server demands a fresh re-authentication, asks for
/// it and retries once.
Future<T?> withStepUp<T>(BuildContext context, Future<T> Function() action) async {
  try {
    return await action();
  } on ApiException catch (e) {
    if (!e.stepUpRequired || !context.mounted) rethrow;
    final ok = await showStepUpDialog(context);
    if (!ok) return null;
    return action();
  }
}

Future<bool> showStepUpDialog(BuildContext context) async {
  final t = AppLocalizations.of(context);
  final auth = AppServices.of(context).auth;
  final password = TextEditingController();
  final code = TextEditingController();
  final ok = await showDialog<bool>(
    context: context,
    builder: (c) => AlertDialog(
      title: Text(t.stepUpTitle),
      content: Column(mainAxisSize: MainAxisSize.min, children: [
        Text(t.stepUpPrompt),
        const SizedBox(height: 12),
        TextField(controller: password, obscureText: true, decoration: InputDecoration(labelText: t.password)),
        const SizedBox(height: 8),
        TextField(controller: code, keyboardType: TextInputType.number, maxLength: 6,
            decoration: InputDecoration(labelText: t.mfaCode)),
      ]),
      actions: [
        TextButton(onPressed: () => Navigator.pop(c, false), child: Text(t.cancel)),
        FilledButton(
          onPressed: () async {
            try {
              await auth.stepUp(password.text, code.text.trim());
              if (c.mounted) Navigator.pop(c, true);
            } on ApiException {
              if (c.mounted) toast(c, t.stepUpFailed);
            }
          },
          child: Text(t.verify),
        ),
      ],
    ),
  );
  password.clear();
  return ok ?? false;
}
