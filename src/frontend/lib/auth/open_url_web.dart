import 'package:web/web.dart' as web;

import 'safe_url.dart';

void openExternalUrl(String url) {
  if (!isSafeNavigationUrl(url)) {
    throw ArgumentError('Refusing to navigate to an unsafe URL');
  }
  web.window.location.href = url;
}
