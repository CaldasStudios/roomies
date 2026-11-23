import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:go_router/go_router.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:provider/provider.dart';
import 'package:roomies/api/api_client.dart';
import 'package:roomies/models/models.dart';
import 'package:roomies/state/app_state.dart';
import 'package:roomies/widgets/app_shell.dart';
import 'package:shared_preferences/shared_preferences.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  setUp(() => SharedPreferences.setMockInitialValues({}));

  ApiClient client(int status) => ApiClient(
        baseUrl: 'http://example/api',
        httpClient: MockClient((_) async => http.Response('', status)),
      )..adoptCookieSession();

  test('a 500 keeps the session and throws', () async {
    final api = client(500);
    await expectLater(api.logout(strict: true), throwsA(isA<Object>()));
    expect(api.isAuthenticated, isTrue);
  });

  test('a network error keeps the session', () async {
    final api = ApiClient(
      baseUrl: 'http://example/api',
      httpClient: MockClient((_) async => throw Exception('offline')),
    )..adoptCookieSession();
    await expectLater(api.logout(strict: true), throwsA(isA<Object>()));
    expect(api.isAuthenticated, isTrue);
  });

  for (final status in [200, 204, 401]) {
    test('a $status clears the session', () async {
      final api = client(status);
      await api.logout(strict: true);
      expect(api.isAuthenticated, isFalse);
    });
  }

  test('best-effort cleanup clears even on 500', () async {
    final api = client(500);
    await api.logout();
    expect(api.isAuthenticated, isFalse);
  });

  testWidgets('Log out shows an error and stays signed in on failure',
      (tester) async {
    final appState = AppState(client(500), deviceLocale: 'en')
      ..sessionReady = true
      ..user = User(
        id: 'u1',
        email: 'a@example.com',
        name: 'A',
        createdAt: '2026-01-01T00:00:00Z',
      );
    final router = GoRouter(
      initialLocation: '/dashboard',
      routes: [
        GoRoute(path: '/', builder: (_, __) => const Text('sign-in')),
        GoRoute(
          path: '/dashboard',
          builder: (_, __) => AppShell(child: const Text('body')),
        ),
        GoRoute(path: '/settings', builder: (_, __) => const SizedBox()),
      ],
    );
    await tester.binding.setSurfaceSize(const Size(1200, 900));
    addTearDown(() => tester.binding.setSurfaceSize(null));
    await tester.pumpWidget(
      ChangeNotifierProvider.value(
        value: appState,
        child: MaterialApp.router(routerConfig: router),
      ),
    );
    await tester.pumpAndSettle();

    await tester.tap(find.text('Log out'));
    // pumpAndSettle would outlast the snackbar.
    await tester.pump();
    await tester.pump(const Duration(milliseconds: 500));

    expect(find.text("Couldn't sign out, try again."), findsOneWidget);
    expect(find.text('sign-in'), findsNothing);
    expect(appState.user, isNotNull);
    expect(appState.api.isAuthenticated, isTrue);
  });
}
