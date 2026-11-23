import 'dart:convert';
import 'dart:math';

import 'package:crypto/crypto.dart';
import 'package:flutter/foundation.dart';
import 'package:flutter_web_auth_2/flutter_web_auth_2.dart';

import '../api/api_client.dart';
import '../api/api_error.dart';
import '../l10n/strings.dart';
import '../models/models.dart';

const nativeCallbackScheme = 'app.roomies.roomies';

enum SignInMode { web, native, unsupported }

/// Web and Android sign in through the backend; desktop has no sign-in yet.
SignInMode currentSignInMode() {
  if (kIsWeb) return SignInMode.web;
  return defaultTargetPlatform == TargetPlatform.android
      ? SignInMode.native
      : SignInMode.unsupported;
}

/// A PKCE verifier and its S256 challenge.
({String verifier, String challenge}) createPkcePair([Random? random]) {
  final rng = random ?? Random.secure();
  final bytes = List<int>.generate(32, (_) => rng.nextInt(256));
  final verifier = base64Url.encode(bytes).replaceAll('=', '');
  final challenge =
      base64Url.encode(sha256.convert(ascii.encode(verifier)).bytes)
          .replaceAll('=', '');
  return (verifier: verifier, challenge: challenge);
}

/// Opens the system browser sign-in and exchanges the returned one-time code.
/// Throws [ApiError] on exchange failure, [SignInProviderError] when the
/// provider or backend reports one, [SignInCancelled] if the user backs out.
Future<AuthResponse> signInNative(ApiClient api) async {
  final pkce = createPkcePair();
  final String result;
  try {
    result = await FlutterWebAuth2.authenticate(
      url: api.oidcNativeUrl(pkce.challenge),
      callbackUrlScheme: nativeCallbackScheme,
    );
  } catch (_) {
    throw SignInCancelled();
  }
  final params = Uri.parse(result).queryParameters;
  final error = params['error'];
  if (error != null && error.isNotEmpty) throw SignInProviderError(error);
  final code = params['code'] ?? '';
  if (code.isEmpty) throw SignInProviderError('missing_code');
  return api.exchangeOidcCode(code, pkce.verifier);
}

class SignInCancelled implements Exception {}

class SignInProviderError implements Exception {
  SignInProviderError(this.code);
  final String code;
}

/// Localized text for an `auth_error` code from the backend's web redirect
/// (or the `error` of the Android deep link).
String describeAuthErrorCode(String code, RoomiesStrings s) => switch (code) {
      'email_unverified' => s.signInEmailNotVerified,
      'email_in_use' => s.signInEmailInUse,
      'provider' || 'access_denied' => s.signInDenied,
      _ => s.signInFailed,
    };

/// Localized, user-facing text for a failed sign-in.
String describeSignInError(Object error, RoomiesStrings s) {
  if (error is SignInProviderError) return describeAuthErrorCode(error.code, s);
  if (error is ApiError) {
    if (error.type == ApiErrorType.transport) return s.serverUnreachable;
    return switch (error.status) {
      403 => s.signInEmailNotVerified,
      409 => s.signInEmailInUse,
      _ => s.signInFailed,
    };
  }
  return s.signInFailed;
}
