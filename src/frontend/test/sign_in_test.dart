import 'dart:convert';
import 'dart:math';

import 'package:crypto/crypto.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:roomies/api/api_client.dart';
import 'package:roomies/api/api_error.dart';
import 'package:roomies/auth/sign_in.dart';
import 'package:roomies/l10n/strings.dart';

void main() {
  const s = RoomiesStrings('en');

  test('sign-in errors map to localized messages', () {
    expect(describeSignInError(ApiError.http(403, 'email not verified'), s),
        s.signInEmailNotVerified);
    expect(describeSignInError(ApiError.http(409, 'conflict'), s),
        s.signInEmailInUse);
    expect(describeSignInError(ApiError.http(401, 'authentication failed'), s),
        s.signInFailed);
    expect(describeSignInError(ApiError.transport('socket'), s),
        s.serverUnreachable);
    expect(describeSignInError(SignInProviderError('access_denied'), s),
        s.signInDenied);
    expect(describeSignInError(SignInProviderError('server_error'), s),
        s.signInFailed);
    expect(describeSignInError(StateError('x'), s), s.signInFailed);
  });

  test('auth_error codes map to localized messages', () {
    expect(describeAuthErrorCode('email_unverified', s),
        s.signInEmailNotVerified);
    expect(describeAuthErrorCode('email_in_use', s), s.signInEmailInUse);
    expect(describeAuthErrorCode('provider', s), s.signInDenied);
    expect(describeAuthErrorCode('failed', s), s.signInFailed);
    expect(describeAuthErrorCode('<script>', s), s.signInFailed);
  });

  test('PKCE challenge is the S256 of the verifier', () {
    final pkce = createPkcePair(Random(1));
    final expected = base64Url
        .encode(sha256.convert(ascii.encode(pkce.verifier)).bytes)
        .replaceAll('=', '');
    expect(pkce.challenge, expected);
    expect(pkce.verifier.length, greaterThanOrEqualTo(43));
  });

  test('native sign-in url carries the app challenge', () {
    final api = ApiClient(baseUrl: 'https://roomies.example/api');
    expect(api.oidcNativeUrl('abc'),
        'https://roomies.example/api/auth/oidc/native?app_challenge=abc');
  });
}
