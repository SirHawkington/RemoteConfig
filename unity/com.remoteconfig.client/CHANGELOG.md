# Changelog

## 0.1.0

First release.

- Heartbeat to the agent (state, uptime, build, FPS, config revision, custom status values).
- Live config with hot reload: long-poll with ETags, typed path lookups, last-known-good config from disk
  when the agent is unreachable, failed applies reported back to the dashboard.
- Quit hook: `QuitRequested` with the agent's reason and grace period, plus normal window-close handling.
- Metrics and events, batched; `Debug.LogError`/exceptions forwarded with a rate limit.
- Starts itself when launched by the agent (environment variables); `RemoteConfigClient.Create` and a
  component for explicit setup.
- Test scene sample, EditMode and PlayMode tests (against a fake agent).
