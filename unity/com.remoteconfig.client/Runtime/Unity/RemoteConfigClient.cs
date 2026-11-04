using System;
using System.Collections.Generic;
using Newtonsoft.Json.Linq;
using UnityEngine;

namespace RemoteConfig
{
    /// <summary>
    /// The component that connects a Unity app to the RemoteConfig agent.
    ///
    /// When the agent launches the app there is nothing to set up: the agent passes its address
    /// and token in environment variables and this component is created automatically. Add it
    /// to a scene (GameObject &gt; RemoteConfig &gt; Add Client) only to run in the editor, to
    /// override the settings, or to control when it starts.
    ///
    ///   RemoteConfigClient.OnConfig(cfg => volume = RemoteConfigClient.Get("audio.volume", 0.8f));
    ///   RemoteConfigClient.Instance.QuitRequested += q => SaveEverything();
    ///   RemoteConfigClient.Instance.ReportMetric("visitors_today", 42);
    /// </summary>
    [DisallowMultipleComponent]
    [DefaultExecutionOrder(-1000)] // before your scripts, so Awake/Start of others can already read config
    [AddComponentMenu("RemoteConfig/Remote Config Client")]
    public sealed class RemoteConfigClient : MonoBehaviour, IAppProbe
    {
        [Header("Connection (leave empty to use what the agent provides)")]
        [Tooltip("e.g. http://127.0.0.1:7878/v1. Empty: REMOTECONFIG_URL, then the agent's default address.")]
        [SerializeField] string baseUrl = "";
        [Tooltip("Empty: REMOTECONFIG_TOKEN, then the token file the agent keeps.")]
        [SerializeField] string token = "";
        [Tooltip("The agent's effective-config.json, used until the agent answers. Empty: REMOTECONFIG_CONFIG_FILE.")]
        [SerializeField] string configFilePath = "";

        [Header("Behaviour")]
        [SerializeField] float heartbeatSeconds = 10f;
        [Tooltip("Empty: Application.version.")]
        [SerializeField] string buildVersion = "";
        [Tooltip("Call Application.Quit() when the agent asks the app to shut down. If off, handle QuitRequested yourself; the agent kills the app after the grace period.")]
        [SerializeField] bool quitWhenAsked = true;
        [Tooltip("Show Debug.LogError and exceptions on the device's dashboard page.")]
        [SerializeField] bool forwardErrors = true;
        [SerializeField] bool dontDestroyOnLoad = true;

        static RemoteConfigOptions s_pendingOptions; // handed to Awake by Create()

        public static RemoteConfigClient Instance { get; private set; }

        RemoteConfigSession _session;
        volatile float _smoothedFps;
        volatile float _uptime;

        /// <summary>The underlying session, for advanced use.</summary>
        public RemoteConfigSession Session => _session;

        /// <summary>A new config revision is in effect. Also raised at startup for the on-disk config.</summary>
        public event Action<ConfigDocument> ConfigChanged;

        /// <summary>The agent wants the app to save and exit (restart, scheduled restart, config change...).</summary>
        public event Action<QuitRequest> QuitRequested;

        public bool IsConnected => _session != null && _session.AgentReachable;
        public ConfigDocument Config => _session?.Config.Current;
        public int ConfigRevision => _session?.Config.Revision ?? 0;

        double IAppProbe.Fps => _smoothedFps;
        double IAppProbe.UptimeSeconds => _uptime;

        // ------------------------------------------------------------ creation

        /// <summary>Creates a client from code, with explicit options (instead of adding the component in a scene).</summary>
        public static RemoteConfigClient Create(RemoteConfigOptions options, bool persistAcrossScenes = true)
        {
            if (Instance != null) throw new InvalidOperationException("a RemoteConfigClient already exists");
            var go = new GameObject("RemoteConfig");
            go.SetActive(false); // so the options are in place before Awake runs
            var client = go.AddComponent<RemoteConfigClient>();
            client.dontDestroyOnLoad = persistAcrossScenes;
            s_pendingOptions = options;
            go.SetActive(true);
            return client;
        }

        [RuntimeInitializeOnLoadMethod(RuntimeInitializeLoadType.SubsystemRegistration)]
        static void ResetStatics()
        {
            Instance = null; // for "enter play mode without domain reload"
            s_pendingOptions = null;
        }

        void Awake()
        {
            if (Instance != null && Instance != this)
            {
                Destroy(this); // one is enough
                return;
            }
            Instance = this;
            if (dontDestroyOnLoad && transform.parent == null) DontDestroyOnLoad(gameObject);

            var options = s_pendingOptions ?? ResolveOptions();
            s_pendingOptions = null;
            if (string.IsNullOrEmpty(options.BuildVersion)) options.BuildVersion = Application.version;
#if !UNITY_EDITOR
            if (!Application.runInBackground)
                Debug.LogWarning("[RemoteConfig] Run In Background is off: if this window ever loses focus the app pauses, " +
                                 "stops sending heartbeats, and the agent will restart it as hung. Enable it in " +
                                 "Player Settings > Resolution and Presentation > Run In Background.");
#endif

            _session = new RemoteConfigSession(options, new UnityWebRequestTransport(options.BaseUrl, options.Token), this,
                msg => Debug.Log("[RemoteConfig] " + msg));
            _session.ConfigChanged += doc => InvokeAll(ConfigChanged, doc, rethrow: true);
            _session.QuitRequested += OnSessionQuitRequested;
            if (options.ForwardErrors) Application.logMessageReceivedThreaded += OnLog;
            _session.Start();
        }

        RemoteConfigOptions ResolveOptions()
        {
            var o = RemoteConfigOptions.FromEnvironment();
            if (!string.IsNullOrEmpty(baseUrl)) o.BaseUrl = baseUrl;
            if (!string.IsNullOrEmpty(token)) o.Token = token;
            if (!string.IsNullOrEmpty(configFilePath)) o.ConfigFilePath = configFilePath;
            o.FillMissingDefaults(); // started by hand: default address, token from the agent's state folder
            o.HeartbeatSeconds = heartbeatSeconds;
            o.BuildVersion = buildVersion;
            o.QuitWhenAsked = quitWhenAsked;
            o.ForwardErrors = forwardErrors;
            return o;
        }

        void Update()
        {
            _uptime = Time.realtimeSinceStartup;
            var dt = Time.unscaledDeltaTime;
            if (dt > 0f) _smoothedFps = _smoothedFps <= 0f ? 1f / dt : Mathf.Lerp(_smoothedFps, 1f / dt, 0.05f);
        }

        void OnDestroy()
        {
            if (Instance == this) Instance = null;
            Application.logMessageReceivedThreaded -= OnLog;
            _session?.Dispose();
        }

        void OnLog(string condition, string stackTrace, LogType type)
        {
            if (type == LogType.Error || type == LogType.Exception || type == LogType.Assert)
                _session?.ForwardError(condition, stackTrace);
        }

        void OnSessionQuitRequested(QuitRequest request)
        {
            Debug.Log($"[RemoteConfig] the agent asked the app to quit: {request.Reason} ({request.GraceSeconds}s to finish)");
            InvokeAll(QuitRequested, request, rethrow: false);
            if (!_session.Options.QuitWhenAsked) return;
#if UNITY_EDITOR
            UnityEditor.EditorApplication.isPlaying = false;
#else
            Application.Quit();
#endif
        }

        /// <summary>
        /// Calls every subscriber even if one throws (a plain event invocation stops at the first
        /// throw and silently starves the rest). Each exception is logged; with
        /// <paramref name="rethrow"/> the first is thrown afterwards so the caller can report it,
        /// which is how a handler that cannot apply a config ends up as a failed ack on the dashboard.
        /// </summary>
        static void InvokeAll<T>(Action<T> handlers, T argument, bool rethrow)
        {
            if (handlers == null) return;
            Exception first = null;
            foreach (var handler in handlers.GetInvocationList())
            {
                try { ((Action<T>)handler)(argument); }
                catch (Exception e)
                {
                    first = first ?? e;
                    Debug.LogException(e);
                }
            }
            if (rethrow && first != null) System.Runtime.ExceptionServices.ExceptionDispatchInfo.Capture(first).Throw();
        }

        // ------------------------------------------------------------ using config

        /// <summary>Typed lookup by path, e.g. Get("audio.volume", 0.8f) or Get("items[0].name", "").</summary>
        public static T Get<T>(string path, T fallback = default(T))
            => Instance != null && Instance._session != null ? Instance._session.Config.Get(path, fallback) : fallback;

        public static bool TryGet<T>(string path, out T value)
        {
            value = default(T);
            return Instance != null && Instance._session != null && Instance._session.Config.TryGet(path, out value);
        }

        /// <summary>
        /// Calls <paramref name="handler"/> now if a config is already held (the last known one counts),
        /// and again whenever a new revision takes effect. Safe to call from Awake or Start.
        /// Returns a function that unsubscribes.
        /// </summary>
        public static Action OnConfig(Action<ConfigDocument> handler, bool invokeNow = true)
        {
            var client = Instance;
            if (client == null) return () => { };
            client.ConfigChanged += handler;
            var current = client.Config;
            if (invokeNow && current != null) handler(current);
            return () => { if (client != null) client.ConfigChanged -= handler; };
        }

        // ------------------------------------------------------------ telling the dashboard things

        /// <summary>The state shown next to the device (running, loading, idle, error) and an optional short message.</summary>
        public void SetState(AppState state, string message = null) => _session?.SetState(state, message);

        /// <summary>Live status shown on the device page, e.g. SetStatus("scene", "Lobby"). Null removes it.</summary>
        public void SetStatus(string key, object value) => _session?.SetStatus(key, value);

        /// <summary>A numeric reading (visitors, queue length, temperature). Batched, so cheap to call often.</summary>
        public void ReportMetric(string name, double value, IDictionary<string, string> tags = null) => _session?.ReportMetric(name, value, tags);

        /// <summary>Something the operator should be able to see in the device's event list.</summary>
        public void ReportEvent(string type, string message = "", EventLevel level = EventLevel.Info, IDictionary<string, object> data = null)
            => _session?.ReportEvent(type, message, level, data);
    }
}
