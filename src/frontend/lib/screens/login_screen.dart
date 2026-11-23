import 'package:flutter/material.dart';
import 'package:go_router/go_router.dart';
import 'package:provider/provider.dart';

import '../api/api_error.dart';
import '../auth/open_url.dart';
import '../auth/sign_in.dart';
import '../models/models.dart';
import '../state/app_state.dart';
import '../widgets/roomies_ui.dart';

/// Auth entry: one "Continue with {provider}" button. Sign-up happens on the
/// provider's own pages. Desktop builds only show a note.
class LoginScreen extends StatefulWidget {
  const LoginScreen({super.key, this.mode});

  /// Overrides the platform-derived sign-in mode (tests).
  final SignInMode? mode;

  @override
  State<LoginScreen> createState() => _LoginScreenState();
}

class _LoginScreenState extends State<LoginScreen> {
  AuthConfig? _config;
  var _loading = false;
  var _configLoading = true;
  var _configFailed = false;
  String? _error;

  SignInMode get _mode => widget.mode ?? currentSignInMode();

  @override
  void initState() {
    super.initState();
    final app = context.read<AppState>();
    final authError = app.authError;
    app.authError = null;
    if (authError != null) {
      _error = describeAuthErrorCode(authError, app.strings);
    }
    WidgetsBinding.instance.addPostFrameCallback((_) {
      if (_mode != SignInMode.unsupported) _loadConfig();
    });
  }

  Future<void> _loadConfig() async {
    setState(() {
      if (_configFailed) _error = null;
      _configLoading = true;
      _configFailed = false;
    });
    try {
      final config = await context.read<AppState>().api.getAuthConfig();
      if (!mounted) return;
      setState(() {
        _config = config;
        _configLoading = false;
      });
    } catch (error) {
      if (!mounted) return;
      // Don't guess whether sign-in is configured; offer a retry.
      setState(() {
        _configLoading = false;
        _configFailed = true;
        _error = describeError(
          error,
          unreachable: context.read<AppState>().strings.serverUnreachable,
        );
      });
    }
  }

  Future<void> _signIn() async {
    setState(() {
      _loading = true;
      _error = null;
    });
    final app = context.read<AppState>();
    final navigator = GoRouter.of(context);
    try {
      if (_mode == SignInMode.web) {
        openExternalUrl(await app.api.oidcAuthorizeUrl());
        return;
      }
      final auth = await signInNative(app.api);
      await app.setUser(auth.user);
      if (!mounted) return;
      final pending = await app.api.loadPendingInvitation();
      if (pending != null && pending.isNotEmpty) {
        navigator.go('/accept-invitation');
      } else {
        navigator.go('/dashboard');
      }
    } on SignInCancelled {
      // The user backed out of the browser; nothing to report.
    } catch (error) {
      if (mounted) {
        setState(() => _error = describeSignInError(error, app.strings));
      }
    } finally {
      if (mounted) setState(() => _loading = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    final s = context.watch<AppState>().strings;
    final desktop = _mode == SignInMode.unsupported;

    return RoomiesAuthFrame(
      strings: s,
      onOpenSettings: () => context.go('/settings'),
      footer: s.privacyLine,
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          if (_error != null) RoomiesError(_error!),
          if (desktop)
            Text(
              s.signInDesktopNote,
              textAlign: TextAlign.center,
              style: Theme.of(context).textTheme.bodyLarge,
            )
          else if (_configLoading)
            const Padding(
              padding: EdgeInsets.symmetric(vertical: 12),
              child: Center(child: CircularProgressIndicator(strokeWidth: 2.5)),
            )
          else if (_configFailed)
            OutlinedButton(onPressed: _loadConfig, child: Text(s.retry))
          else if (_mode == SignInMode.native && _config?.oidcNative != true)
            Text(
              s.signInNativeOffNote,
              textAlign: TextAlign.center,
              style: Theme.of(context).textTheme.bodyLarge,
            )
          else if (_config?.oidc == true)
            FilledButton(
              onPressed: _loading ? null : _signIn,
              style: FilledButton.styleFrom(
                minimumSize: const Size.fromHeight(52),
                textStyle: Theme.of(context).textTheme.labelLarge?.copyWith(
                      fontSize: 16,
                    ),
              ),
              child: Text(_loading
                  ? s.redirecting
                  : s.continueWith(_config!.oidcName)),
            ),
        ],
      ),
    );
  }
}
