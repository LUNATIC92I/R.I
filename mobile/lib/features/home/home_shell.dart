import 'package:flutter/material.dart';

import '../../core/services.dart';
import '../../l10n/app_localizations.dart';
import '../admin/admin_screens.dart';
import '../analysis/analysis_screens.dart';
import '../cases/case_list_screen.dart';
import '../profile/profile_screens.dart';
import 'dashboard_screens.dart';

class HomeShell extends StatefulWidget {
  const HomeShell({super.key});

  @override
  State<HomeShell> createState() => _HomeShellState();
}

class _HomeShellState extends State<HomeShell> {
  int _index = 0;

  @override
  Widget build(BuildContext context) {
    final t = AppLocalizations.of(context);
    final me = AppServices.of(context).auth.me!;
    final pages = <Widget>[
      const DashboardScreen(),
      if (me.can('case:read')) const CaseListScreen(),
      const AlertsScreen(),
      if (me.can('search:use')) const SearchScreen(),
      const MoreScreen(),
    ];
    final items = <NavigationDestination>[
      NavigationDestination(icon: const Icon(Icons.space_dashboard_outlined), label: t.dashboard),
      if (me.can('case:read')) NavigationDestination(icon: const Icon(Icons.folder_outlined), label: t.cases),
      NavigationDestination(icon: const Icon(Icons.notification_important_outlined), label: t.alerts),
      if (me.can('search:use')) NavigationDestination(icon: const Icon(Icons.search), label: t.search),
      NavigationDestination(icon: const Icon(Icons.menu), label: t.more),
    ];
    final index = _index.clamp(0, pages.length - 1);
    return Scaffold(
      body: SafeArea(child: IndexedStack(index: index, children: pages)),
      bottomNavigationBar: NavigationBar(
        selectedIndex: index,
        onDestinationSelected: (i) => setState(() => _index = i),
        destinations: items,
      ),
    );
  }
}

class _Entry {
  const _Entry(this.icon, this.label, this.builder, {this.permission});

  final IconData icon;
  final String label;
  final WidgetBuilder builder;
  final String? permission;
}

class MoreScreen extends StatelessWidget {
  const MoreScreen({super.key});

  @override
  Widget build(BuildContext context) {
    final t = AppLocalizations.of(context);
    final auth = AppServices.of(context).auth;
    final me = auth.me!;
    final entries = <_Entry>[
      _Entry(Icons.public, t.osint, (_) => const CasePickerScreen(target: CaseModule.osint), permission: 'case:read'),
      _Entry(Icons.lan_outlined, t.cyber, (_) => const CasePickerScreen(target: CaseModule.cyber), permission: 'case:read'),
      _Entry(Icons.timeline, t.timeline, (_) => const TimelineScreen(), permission: 'case:read'),
      _Entry(Icons.map_outlined, t.map, (_) => const MapScreen(), permission: 'case:read'),
      _Entry(Icons.hub_outlined, t.graph, (_) => const CasePickerScreen(target: CaseModule.graph), permission: 'case:read'),
      _Entry(Icons.description_outlined, t.reports, (_) => const CasePickerScreen(target: CaseModule.reports),
          permission: 'case:read'),
      _Entry(Icons.notifications_none, t.notifications, (_) => const NotificationsScreen()),
      _Entry(Icons.person_outline, t.profile, (_) => const ProfileScreen()),
      _Entry(Icons.smartphone, t.devices, (_) => const DevicesScreen()),
      _Entry(Icons.admin_panel_settings_outlined, t.administration, (_) => const AdminScreen(),
          permission: 'user:manage'),
      _Entry(Icons.fact_check_outlined, t.auditLog, (_) => const AuditScreen(), permission: 'audit:read'),
      _Entry(Icons.security, t.securitySettings, (_) => const SecuritySettingsScreen()),
    ];
    final visible = entries.where((e) => e.permission == null || me.can(e.permission!));
    return Scaffold(
      appBar: AppBar(title: Text(t.more)),
      body: ListView(children: [
        ListTile(
          leading: const Icon(Icons.badge_outlined),
          title: Text(me.displayName),
          subtitle: Text('${me.professionalId}  ·  ${me.roleLabel(Localizations.localeOf(context).languageCode)}'),
        ),
        const Divider(),
        for (final e in visible)
          ListTile(
            leading: Icon(e.icon),
            title: Text(e.label),
            trailing: const Icon(Icons.chevron_right),
            onTap: () => Navigator.of(context).push(MaterialPageRoute(builder: e.builder)),
          ),
        const Divider(),
        ListTile(
          leading: const Icon(Icons.logout),
          title: Text(t.logout),
          onTap: () async {
            if (await confirmLogout(context)) await auth.logout();
          },
        ),
      ]),
    );
  }
}

Future<bool> confirmLogout(BuildContext context) async {
  final t = AppLocalizations.of(context);
  final r = await showDialog<bool>(
    context: context,
    builder: (c) => AlertDialog(
      title: Text(t.logout),
      content: Text(t.logoutConfirm),
      actions: [
        TextButton(onPressed: () => Navigator.pop(c, false), child: Text(t.cancel)),
        FilledButton(onPressed: () => Navigator.pop(c, true), child: Text(t.confirm)),
      ],
    ),
  );
  return r ?? false;
}
