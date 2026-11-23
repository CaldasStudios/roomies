import 'package:web/web.dart' as web;

/// Reads the `auth_error` code the backend adds to the post-sign-in redirect
/// and removes it from the address bar, keeping the rest of the URL.
String? takeAuthError() {
  final uri = Uri.parse(web.window.location.href);
  final code = uri.queryParameters['auth_error'];
  if (code == null) return null;
  final query = Map.of(uri.queryParameters)..remove('auth_error');
  final clean = uri.replace(queryParameters: query.isEmpty ? null : query);
  final search = clean.hasQuery ? '?${clean.query}' : '';
  final hash = clean.hasFragment ? '#${clean.fragment}' : '';
  web.window.history.replaceState(null, '', '${clean.path}$search$hash');
  return code;
}
