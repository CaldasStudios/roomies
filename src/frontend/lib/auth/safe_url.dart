/// Only https URLs (http for loopback hosts) are ever navigated to.
bool isSafeNavigationUrl(String url) {
  final uri = Uri.tryParse(url);
  if (uri == null || uri.host.isEmpty) return false;
  if (uri.scheme == 'https') return true;
  if (uri.scheme != 'http') return false;
  final host = uri.host.toLowerCase();
  return host == 'localhost' ||
      host == '127.0.0.1' ||
      host.endsWith('.localhost');
}
