import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:go_router/go_router.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:provider/provider.dart';
import 'package:roomies/api/api_client.dart';
import 'package:roomies/auth/sign_in.dart';
import 'package:roomies/screens/login_screen.dart';
import 'package:roomies/state/app_state.dart';
import 'package:roomies/theme/roomies_theme.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  Future<void> pumpLogin(WidgetTester tester, http.Client client,
      {SignInMode mode = SignInMode.web, String? authError}) async {
    final appState = AppState(
      ApiClient(baseUrl: 'http://example/api', httpClient: client),
      deviceLocale: 'en-US',
    )
      ..sessionReady = true
      ..authError = authError;
    final router = GoRouter(
      routes: [
        GoRoute(path: '/', builder: (_, __) => LoginScreen(mode: mode)),
        GoRoute(path: '/settings', builder: (_, __) => const Text('settings')),
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
  }

  testWidgets('sign-in offers Settings instead of a language toggle',
      (tester) async {
    await pumpLogin(
      tester,
      MockClient((_) async => http.Response(
            '{"oidc":true,"oidc_name":"CaldasStudios"}',
            200,
          )),
    );
    expect(find.text('Continue with CaldasStudios'), findsOneWidget);
    expect(find.text('PT'), findsNothing);
    await tester.tap(find.byTooltip('Settings'));
    await tester.pumpAndSettle();
    expect(find.text('settings'), findsOneWidget);
  });

  testWidgets('server errors read as unreachable and can be retried',
      (tester) async {
    var calls = 0;
    await pumpLogin(
      tester,
      MockClient((_) async {
        calls++;
        return calls == 1
            ? http.Response('', 502)
            : http.Response('{"oidc":true,"oidc_name":"CaldasStudios"}', 200);
      }),
    );
    expect(find.textContaining("Can't reach Roomies"), findsOneWidget);
    expect(find.text('502'), findsNothing);
    // No guessed sign-in button while the config is unknown.
    expect(find.textContaining('Continue with'), findsNothing);

    await tester.tap(find.text('Retry'));
    await tester.pumpAndSettle();
    expect(find.text('Continue with CaldasStudios'), findsOneWidget);
    expect(find.textContaining("Can't reach Roomies"), findsNothing);
  });

  testWidgets('desktop shows a note instead of a sign-in button',
      (tester) async {
    var calls = 0;
    await pumpLogin(
      tester,
      MockClient((_) async {
        calls++;
        return http.Response('{"oidc":true,"oidc_name":"CaldasStudios"}', 200);
      }),
      mode: SignInMode.unsupported,
    );
    expect(find.textContaining('web and Android'), findsOneWidget);
    expect(find.textContaining('Continue with'), findsNothing);
    expect(calls, 0);
  });

  testWidgets('web redirect auth_error shows a localized message once',
      (tester) async {
    await pumpLogin(
      tester,
      MockClient((_) async =>
          http.Response('{"oidc":true,"oidc_name":"CaldasStudios"}', 200)),
      authError: 'email_unverified',
    );
    expect(find.textContaining('Verify your email'), findsOneWidget);
    expect(find.text('Continue with CaldasStudios'), findsOneWidget);
  });

  Future<void> pumpNative(WidgetTester tester, String body) => pumpLogin(
        tester,
        MockClient((_) async => http.Response(body, 200)),
        mode: SignInMode.native,
      );

  testWidgets('android shows the button when the server enables native',
      (tester) async {
    await pumpNative(
        tester, '{"oidc":true,"oidc_name":"CaldasStudios","oidc_native":true}');
    expect(find.text('Continue with CaldasStudios'), findsOneWidget);
  });

  testWidgets('android shows a note when native sign-in is off or missing',
      (tester) async {
    await pumpNative(tester,
        '{"oidc":true,"oidc_name":"CaldasStudios","oidc_native":false}');
    expect(find.textContaining('turned off by the server'), findsOneWidget);
    expect(find.textContaining('Continue with'), findsNothing);

    await pumpNative(tester, '{"oidc":true,"oidc_name":"CaldasStudios"}');
    expect(find.textContaining('turned off by the server'), findsOneWidget);
    expect(find.textContaining('Continue with'), findsNothing);
  });

  testWidgets('web ignores oidc_native', (tester) async {
    await pumpLogin(
      tester,
      MockClient((_) async =>
          http.Response('{"oidc":true,"oidc_name":"CaldasStudios"}', 200)),
    );
    expect(find.text('Continue with CaldasStudios'), findsOneWidget);
  });
}
