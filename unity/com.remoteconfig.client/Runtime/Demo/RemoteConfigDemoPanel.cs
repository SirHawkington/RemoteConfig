using System.Collections.Generic;
using Newtonsoft.Json;
using UnityEngine;

namespace RemoteConfig
{
    /// <summary>
    /// A small on-screen test bench for the client. It makes the camera colour, a spinning
    /// cube and a title follow the remote config, so editing the config in the dashboard
    /// changes what you see within a moment, and it has buttons for everything the client can send.
    ///
    /// Config keys it reads (all optional):
    ///   "background"  a colour such as "#204060"
    ///   "spin_speed"  degrees per second
    ///   "title"       text shown at the top
    /// </summary>
    [AddComponentMenu("RemoteConfig/Demo Panel")]
    public sealed class RemoteConfigDemoPanel : MonoBehaviour
    {
        [SerializeField] Camera targetCamera;
        [SerializeField] Transform spinner;

        string _title = "RemoteConfig test scene";
        float _spinSpeed = 30f;
        string _lastQuit = "none";
        string _lastAction = "";
        int _configEvents;
        System.Action _unsubscribe;
        Vector2 _scroll;
        int _clicks;

        void Start()
        {
            if (RemoteConfigClient.Instance == null)
                RemoteConfigClient.Create(RemoteConfigOptions.FromEnvironment().FillMissingDefaults());
            var client = RemoteConfigClient.Instance;
            _unsubscribe = RemoteConfigClient.OnConfig(Apply);
            client.QuitRequested += OnQuit;
        }

        void OnDestroy()
        {
            _unsubscribe?.Invoke();
            if (RemoteConfigClient.Instance != null) RemoteConfigClient.Instance.QuitRequested -= OnQuit;
        }

        void Apply(ConfigDocument doc)
        {
            _configEvents++;
            _title = RemoteConfigClient.Get("title", _title);
            _spinSpeed = RemoteConfigClient.Get("spin_speed", _spinSpeed);
            var background = RemoteConfigClient.Get("background", "");
            if (targetCamera != null && ColorUtility.TryParseHtmlString(background, out var colour))
                targetCamera.backgroundColor = colour;
            Debug.Log($"[RemoteConfigDemo] applied revision {doc.Revision}: title=\"{_title}\" spin_speed={_spinSpeed} background=\"{background}\"");
        }

        void OnQuit(QuitRequest q)
        {
            _lastQuit = $"{q.Reason} ({q.GraceSeconds}s)";
        }

        void Update()
        {
            if (spinner != null) spinner.Rotate(0f, _spinSpeed * Time.deltaTime, 0f);
        }

        void OnGUI()
        {
            var client = RemoteConfigClient.Instance;
            var scale = Mathf.Max(1f, Screen.height / 720f);
            GUI.matrix = Matrix4x4.Scale(new Vector3(scale, scale, 1f));
            var width = Mathf.Min(520f, Screen.width / scale - 20f);
            GUILayout.BeginArea(new Rect(10, 10, width, Screen.height / scale - 20f), GUI.skin.box);

            GUILayout.Label($"<size=20><b>{_title}</b></size>", new GUIStyle(GUI.skin.label) { richText = true });
            if (client == null)
            {
                GUILayout.Label("No RemoteConfigClient.");
                GUILayout.EndArea();
                return;
            }

            GUILayout.Label($"Agent: {(client.IsConnected ? "connected" : "not reachable (running on the last known config)")}");
            GUILayout.Label($"Config revision: {client.ConfigRevision}   (changes applied: {_configEvents})");
            GUILayout.Label($"Last quit request: {_lastQuit}");
            if (_lastAction.Length > 0) GUILayout.Label(_lastAction);

            GUILayout.BeginHorizontal();
            if (GUILayout.Button("Metric")) Do(() => client.ReportMetric("demo_clicks", ++_clicks), "sent metric demo_clicks = " + _clicks);
            if (GUILayout.Button("Event")) Do(() => client.ReportEvent("demo.button", "pressed " + _clicks, EventLevel.Info), "sent event demo.button");
            if (GUILayout.Button("Warn")) Do(() => client.ReportEvent("demo.warn", "something odd", EventLevel.Warn), "sent a warning event");
            GUILayout.EndHorizontal();
            GUILayout.BeginHorizontal();
            if (GUILayout.Button("State: loading")) Do(() => client.SetState(AppState.Loading, "demo loading"), "state = loading");
            if (GUILayout.Button("State: running")) Do(() => client.SetState(AppState.Running), "state = running");
            if (GUILayout.Button("State: error")) Do(() => client.SetState(AppState.Error, "demo error"), "state = error");
            GUILayout.EndHorizontal();
            if (GUILayout.Button("Log an error (forwarded as an event)")) Do(() => Debug.LogError("demo error from the test scene"), "logged an error");

            GUILayout.Label("Config data:");
            _scroll = GUILayout.BeginScrollView(_scroll, GUILayout.Height(160f));
            var doc = client.Config;
            GUILayout.TextArea(doc == null ? "(none yet)" : doc.Data.ToString(Formatting.Indented));
            GUILayout.EndScrollView();
            GUILayout.EndArea();
        }

        void Do(System.Action action, string description)
        {
            action();
            _lastAction = description;
        }
    }
}
