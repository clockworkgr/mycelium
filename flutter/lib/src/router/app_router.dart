import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';

import '../models/node_id.dart';
import '../providers/developer_mode_provider.dart';
import '../screens/conversations_screen.dart';
import '../screens/chat_screen.dart';
import '../screens/contacts_screen.dart';
import '../screens/debug_screen.dart';
import '../screens/groups_screen.dart';
import '../screens/channels_screen.dart';
import '../screens/settings_screen.dart';

final _rootNavigatorKey = GlobalKey<NavigatorState>();

final appRouter = GoRouter(
  navigatorKey: _rootNavigatorKey,
  initialLocation: '/conversations',
  routes: [
    StatefulShellRoute.indexedStack(
      builder: (context, state, navigationShell) {
        return ScaffoldWithNav(navigationShell: navigationShell);
      },
      branches: [
        StatefulShellBranch(routes: [
          GoRoute(
            path: '/conversations',
            builder: (context, state) => const ConversationsScreen(),
            routes: [
              GoRoute(
                path: 'chat/:peerId',
                parentNavigatorKey: _rootNavigatorKey,
                builder: (context, state) {
                  final peerHex = state.pathParameters['peerId']!;
                  return ChatScreen(peerId: NodeId.fromHex(peerHex));
                },
              ),
            ],
          ),
        ]),
        StatefulShellBranch(routes: [
          GoRoute(
            path: '/contacts',
            builder: (context, state) => const ContactsScreen(),
          ),
        ]),
        StatefulShellBranch(routes: [
          GoRoute(
            path: '/groups',
            builder: (context, state) => const GroupsScreen(),
          ),
        ]),
        StatefulShellBranch(routes: [
          GoRoute(
            path: '/channels',
            builder: (context, state) => const ChannelsScreen(),
          ),
        ]),
        StatefulShellBranch(routes: [
          GoRoute(
            path: '/settings',
            builder: (context, state) => const SettingsScreen(),
          ),
        ]),
        StatefulShellBranch(routes: [
          GoRoute(
            path: '/debug',
            builder: (context, state) => const DebugScreen(),
          ),
        ]),
      ],
    ),
  ],
);

class ScaffoldWithNav extends ConsumerWidget {
  final StatefulNavigationShell navigationShell;

  const ScaffoldWithNav({super.key, required this.navigationShell});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final devMode = ref.watch(developerModeProvider);

    final destinations = <NavigationDestination>[
      const NavigationDestination(icon: Icon(Icons.chat), label: 'Chats'),
      const NavigationDestination(icon: Icon(Icons.contacts), label: 'Contacts'),
      const NavigationDestination(icon: Icon(Icons.group), label: 'Groups'),
      const NavigationDestination(icon: Icon(Icons.tag), label: 'Channels'),
      const NavigationDestination(icon: Icon(Icons.settings), label: 'Settings'),
      if (devMode)
        const NavigationDestination(icon: Icon(Icons.bug_report), label: 'Debug'),
    ];

    // If dev mode was turned off while on the debug tab, go back to settings
    final currentIndex = navigationShell.currentIndex;
    final maxIndex = devMode ? 5 : 4;
    final effectiveIndex = (currentIndex > maxIndex) ? 4 : currentIndex;

    if (effectiveIndex != currentIndex) {
      WidgetsBinding.instance.addPostFrameCallback((_) {
        navigationShell.goBranch(4);
      });
    }

    return Scaffold(
      body: navigationShell,
      bottomNavigationBar: NavigationBar(
        selectedIndex: effectiveIndex,
        onDestinationSelected: (index) {
          navigationShell.goBranch(index, initialLocation: index == navigationShell.currentIndex);
        },
        destinations: destinations,
      ),
    );
  }
}
