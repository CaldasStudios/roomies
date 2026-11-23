import 'package:flutter/material.dart';
import 'package:go_router/go_router.dart';

import 'screens/accept_invitation_screen.dart';
import 'screens/dashboard_screen.dart';
import 'screens/house/house_screen.dart';
import 'screens/login_screen.dart';
import 'screens/settings_screen.dart';
import 'state/app_state.dart';

GoRouter createRouter(AppState appState) {
  return GoRouter(
    refreshListenable: appState,
    initialLocation: '/',
    redirect: (context, state) {
      if (!appState.sessionReady) return null;
      final path = state.uri.path;
      final authed = appState.api.isAuthenticated;
      final public = path == '/' ||
          path == '/accept-invitation' ||
          // Language and appearance are reachable before signing in.
          path == '/settings';
      if (!authed && !public) return '/';
      if (authed && path == '/') {
        // Fresh sign-in always goes to Dashboard via explicit
        // navigation. Restored sessions prefer the default house when set.
        return appState.restoredHomePath() ?? '/dashboard';
      }
      return null;
    },
    routes: [
      GoRoute(
        path: '/',
        builder: (context, state) => const LoginScreen(),
      ),
      GoRoute(
        path: '/accept-invitation',
        builder: (context, state) => AcceptInvitationScreen(
          initialToken: state.uri.queryParameters['token'],
        ),
      ),
      GoRoute(
        path: '/dashboard',
        builder: (context, state) => const DashboardScreen(),
      ),
      GoRoute(
        path: '/settings',
        builder: (context, state) => const SettingsScreen(),
      ),
      GoRoute(
        path: '/house/:id',
        builder: (context, state) => HouseScreen(
          houseId: state.pathParameters['id']!,
          initialTab: state.uri.queryParameters['tab'],
        ),
      ),
    ],
    errorBuilder: (context, state) => Scaffold(
      body: Center(child: Text(state.error.toString())),
    ),
  );
}
