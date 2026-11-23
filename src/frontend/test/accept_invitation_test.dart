import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:go_router/go_router.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:provider/provider.dart';
import 'package:roomies/api/api_client.dart';
import 'package:roomies/screens/accept_invitation_screen.dart';
import 'package:roomies/state/app_state.dart';
import 'package:roomies/theme/roomies_theme.dart';
import 'package:shared_preferences/shared_preferences.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  setUp(() => SharedPreferences.setMockInitialValues({}));

  Future<(AppState, ApiClient)> pump(WidgetTester tester, int status,
      {String? initialToken, bool saved = true}) async {
    final api = ApiClient(
      baseUrl: 'http://example/api',
      httpClient: MockClient(
          (_) async => http.Response('{"error":"invitation gone"}', status)),
    )..adoptCookieSession();
    if (saved) await api.savePendingInvitation('dead-token');
    final appState = AppState(api, deviceLocale: 'en-US')
      ..sessionReady = true
      ..pendingInvitation = saved ? 'dead-token' : null;
    final router = GoRouter(
      initialLocation: '/accept-invitation',
      routes: [
        GoRoute(path: '/', builder: (_, __) => const Text('sign-in')),
        GoRoute(
            path: '/dashboard', builder: (_, __) => const Text('dashboard')),
        GoRoute(
            path: '/accept-invitation',
            builder: (_, __) => AcceptInvitationScreen(initialToken: initialToken)),
      ],
    );
    await tester.pumpWidget(
      ChangeNotifierProvider.value(
        value: appState,
        child: MaterialApp.router(
          theme: buildRoomiesTheme(),
          routerConfig: router,
        ),
      ),
    );
    await tester.pumpAndSettle();
    return (appState, api);
  }

  testWidgets('a dead invitation is forgotten and leads to the dashboard',
      (tester) async {
    final (app, api) = await pump(tester, 410);
    expect(find.text('Retry'), findsNothing);
    expect(await api.loadPendingInvitation(), isNull);
    expect(app.pendingInvitation, isNull);
    await tester.tap(find.text('Continue to dashboard'));
    await tester.pumpAndSettle();
    expect(find.text('dashboard'), findsOneWidget);
  });

  testWidgets('a server error keeps the invitation and offers retry',
      (tester) async {
    final (app, api) = await pump(tester, 503);
    expect(find.text('Continue to dashboard'), findsNothing);
    expect(await api.loadPendingInvitation(), 'dead-token');
    expect(app.pendingInvitation, 'dead-token');
    expect(find.byType(FilledButton), findsOneWidget);
  });

  testWidgets('a 400 is terminal', (tester) async {
    final (app, api) = await pump(tester, 400);
    expect(find.text('Continue to dashboard'), findsOneWidget);
    expect(await api.loadPendingInvitation(), isNull);
    expect(app.pendingInvitation, isNull);
  });

  testWidgets('a blank token link is treated as no invitation',
      (tester) async {
    final (_, api) =
        await pump(tester, 400, initialToken: '  ', saved: false);
    expect(await api.loadPendingInvitation(), isNull);
    expect(find.text('Continue to dashboard'), findsOneWidget);
  });
}
