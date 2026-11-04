# RemoteConfig Client (Unity 6)

Connects a Unity app to the RemoteConfig agent on the same machine:

| You get | How |
|---|---|
| **Heartbeat** | The agent restarts a frozen app that stops sending it, and the dashboard shows state, uptime, build, FPS and your own status values. |
| **Live config, hot reload** | Settings you edit in the dashboard reach the running app within seconds, with no restart. Works offline on the last known config. |
| **Quit hook** | When the agent restarts the app (remote restart, scheduled restart, config change) it asks first. You get an event to save state; the app exits by itself. |
| **Metrics and events** | `ReportMetric`, `ReportEvent`, and optionally every `Debug.LogError` shows up on the device page. |

## Install

Package Manager: **+ > Add package from git URL / from disk**, or add to `Packages/manifest.json`:

```json
"com.remoteconfig.client": "file:../path/to/unity/com.remoteconfig.client"
```

It depends on `com.unity.nuget.newtonsoft-json` (installed automatically). Unity 6000.0 or newer.

## Zero code

If the agent launches your app (`supervisor.exe` in the config), the agent hands the app its address and
token through environment variables, and this package **starts itself**. A built player gains heartbeat,
live config and the quit hook without any scene changes. Nothing starts in the editor or when you run
the player by hand unless you add the component (below), so development is unaffected.

Define `REMOTECONFIG_NO_AUTOSTART` in Player Settings to turn auto-start off.

## Use the config

```csharp
using RemoteConfig;

void Start()
{
    // Called now if a config is already known (the last known config counts), and again on every change.
    RemoteConfigClient.OnConfig(doc =>
    {
        volume   = RemoteConfigClient.Get("audio.volume", 0.8f);        // typed, with a default
        language = RemoteConfigClient.Get("ui.language", "en");
        var first = RemoteConfigClient.Get("playlist[0].name", "");     // paths: a.b, a[0].c
    });
}
```

`Get` never throws: a missing key, a null, or a value of the wrong type gives your default. The config is
whatever JSON you put under `data` in the dashboard; see `reload_mode` there for how the operator expects you to react.

If a handler throws, the failure is reported to the dashboard ("config apply failed") and the other handlers still run.

## Handle shutdown

```csharp
RemoteConfigClient.Instance.QuitRequested += request =>
{
    SaveVisitorCounters();   // you have request.GraceSeconds (default 10) before the agent kills the app
    // Application.Quit() is called for you right after the handlers return (see "Quit When Asked").
};
```

The agent also sends a normal window-close, which Unity turns into `Application.wantsToQuit` /
`OnApplicationQuit`, so those work too. Use whichever you prefer.

## Tell the dashboard things

```csharp
var rc = RemoteConfigClient.Instance;
rc.SetState(AppState.Loading, "loading the lobby");      // running | loading | idle | error
rc.SetStatus("scene", "Lobby");                           // live value on the device page
rc.ReportMetric("visitors_today", 42);                    // numbers; batched, cheap to call often
rc.ReportEvent("scene.loaded", "Lobby", EventLevel.Info); // error-level events are sent immediately
```

## Add it to a scene (optional)

**GameObject > RemoteConfig > Add Client**, or `RemoteConfigClient.Create(options)` from code. Fields are
left empty to use what the agent provides. Run the player by hand and it finds the agent at
`127.0.0.1:7878` and its token in the agent's state folder.

| Setting | Default | |
|---|---|---|
| Heartbeat Seconds | 10 | Keep it well below the agent's `heartbeat_timeout_s` (default 60). |
| Quit When Asked | on | Calls `Application.Quit()` after your `QuitRequested` handlers. |
| Forward Errors | on | `Debug.LogError`/exceptions become events (at most 20 a minute). |
| Build Version | `Application.version` | Shown next to the device. |

## Test scene

Import the **Test Scene** sample (Package Manager > RemoteConfig Client > Samples). Press Play with an agent
running, or build it and let the agent launch it. Edit `background`, `spin_speed` or `title` under `data`
in the dashboard's Config tab and watch the scene change live. The on-screen buttons send metrics, events
and state changes, and show the last quit request.

## Good to know

- Everything runs on the main thread (async continuations), so handlers can use the scene directly.
- The client never throws into your game and never blocks a frame: an unreachable agent only means it keeps
  retrying with a growing delay while the app carries on with the config it has.
- `reload_mode: "trigger"` needs the app to expose an HTTP URL; apps using this package should use `watch`
  (the default): the client picks up the change itself and acknowledges it.
- Tested in Unity 6 on Windows (Mono). Other platforms use the same code, but the agent's process
  supervision (adoption, window-close) is Windows-only so far.
