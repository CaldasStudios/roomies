import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:roomies/api/api_client.dart';
import 'package:roomies/main.dart';
import 'package:roomies/router.dart';
import 'package:roomies/state/app_state.dart';

void main() {
  testWidgets('auth_error is shown once and dropped from the URL',
      (tester) async {
    final appState = AppState(
      ApiClient(
        baseUrl: 'http://example/api',
        httpClient: MockClient((_) async =>
            http.Response('{"oidc":true,"oidc_name":"CaldasStudios"}', 200)),
      ),
      deviceLocale: 'en-US',
    )..sessionReady = true;
    final router = createRouter(appState,
        initialLocation: '/?auth_error=email_unverified&keep=1');
    await tester.pumpWidget(RoomiesApp(appState: appState, router: router));
    await tester.pumpAndSettle();

    expect(find.textContaining('Verify your email'), findsOneWidget);
    expect(
      router.routeInformationProvider.value.uri.toString(),
      '/?keep=1',
    );
    expect(appState.authError, isNull);
  });
}
