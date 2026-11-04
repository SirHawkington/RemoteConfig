# Test Scene

`RemoteConfigTestScene.unity` shows the package working. Import it from Package Manager
(RemoteConfig Client > Samples > Test Scene), open it and press Play with the agent running, or build
it and let the agent launch the player.

What follows the remote config (edit these under `data` in the dashboard's Config tab):

| Key | Effect |
|---|---|
| `background` | camera colour, e.g. `"#204060"` |
| `spin_speed` | degrees per second of the cube |
| `title` | text at the top of the panel |

The panel's buttons send a metric, events, a warning and state changes (running / loading / error),
and it shows the last quit request from the agent. "Log an error" shows how `Debug.LogError` turns into an
event on the device page.

If you change the scripts, regenerate the scene with **Tools > RemoteConfig > Create Test Scene**.

Standalone players: enable **Run In Background** in Player Settings. A player that loses focus otherwise
pauses, stops sending heartbeats, and the agent restarts it as hung. (The client logs a warning if it is off.)
