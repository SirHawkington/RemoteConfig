using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Newtonsoft.Json.Linq;

namespace RemoteConfig
{
    /// <summary>
    /// Everything the client does, independent of Unity: four loops that talk to the agent.
    ///
    ///  config     long-polls GET /config; applies new revisions, raises ConfigChanged, acks
    ///  heartbeat  PUT /status every few seconds (the agent restarts a frozen app without one)
    ///  lifecycle  long-polls GET /lifecycle; raises QuitRequested when the agent wants a shutdown
    ///  telemetry  batches events and metrics to POST /events and /metrics
    ///
    /// The loops never throw and never stop: an unreachable agent only means backing off, and
    /// the app keeps running on the config it already has.
    ///
    /// Events are raised on whatever thread the loop resumed on. In Unity that is the main
    /// thread (UnitySynchronizationContext), so handlers may touch the scene.
    /// </summary>
    public sealed class RemoteConfigSession : IDisposable
    {
        readonly RemoteConfigOptions _o;
        readonly IRemoteTransport _transport;
        readonly IAppProbe _probe;
        readonly Action<string> _log;
        readonly CancellationTokenSource _cts = new CancellationTokenSource();

        readonly object _gate = new object();
        AppState _state = AppState.Running;
        string _message = "";
        readonly Dictionary<string, object> _custom = new Dictionary<string, object>();
        readonly List<JObject> _events = new List<JObject>();
        readonly List<JObject> _metrics = new List<JObject>();
        readonly Queue<DateTime> _forwardedErrors = new Queue<DateTime>();
        bool _urgentEvent;
        volatile bool _reachable;
        long _lastContactTicks;

        const int MaxQueued = 500;

        public ConfigStore Config { get; } = new ConfigStore();
        public RemoteConfigOptions Options => _o;

        /// <summary>A new config revision is in effect (also raised for the on-disk fallback at startup).</summary>
        public event Action<ConfigDocument> ConfigChanged;

        /// <summary>The agent wants the app to save and exit. Raised once per request.</summary>
        public event Action<QuitRequest> QuitRequested;

        /// <summary>True while the agent answers.</summary>
        public bool AgentReachable => _reachable;
        public DateTime LastContactUtc => new DateTime(Interlocked.Read(ref _lastContactTicks), DateTimeKind.Utc);
        public QuitRequest LastQuitRequest { get; private set; }
        public AppState State { get { lock (_gate) return _state; } }

        public RemoteConfigSession(RemoteConfigOptions options, IRemoteTransport transport, IAppProbe probe, Action<string> log = null)
        {
            _o = options ?? throw new ArgumentNullException(nameof(options));
            _transport = transport ?? throw new ArgumentNullException(nameof(transport));
            _probe = probe;
            _log = log ?? (_ => { });
        }

        // ------------------------------------------------------------ lifecycle of the session

        public void Start()
        {
            LoadFallbackFile(); // the app has its last known config before the agent has said anything
            var ct = _cts.Token;
            _ = Supervise("config", ConfigLoop, ct);
            _ = Supervise("heartbeat", HeartbeatLoop, ct);
            _ = Supervise("lifecycle", LifecycleLoop, ct);
            _ = Supervise("telemetry", TelemetryLoop, ct);
        }

        public void Dispose() => _cts.Cancel();

        /// <summary>Runs a loop forever; if it ever throws, log it and start it again after a pause.</summary>
        async Task Supervise(string name, Func<CancellationToken, Task> loop, CancellationToken ct)
        {
            while (!ct.IsCancellationRequested)
            {
                try { await loop(ct); return; }
                catch (OperationCanceledException) { return; }
                catch (Exception e)
                {
                    _log($"{name} loop failed, restarting: {e.Message}");
                    await Delay(TimeSpan.FromSeconds(5), ct);
                }
            }
        }

        // ------------------------------------------------------------ what the app tells us

        public void SetState(AppState state, string message = null)
        {
            lock (_gate)
            {
                _state = state;
                _message = message ?? "";
            }
        }

        /// <summary>A small piece of live status that rides along with every heartbeat (shown on the device page).</summary>
        public void SetStatus(string key, object value)
        {
            lock (_gate)
            {
                if (value == null) _custom.Remove(key);
                else _custom[key] = value;
            }
        }

        public void ReportMetric(string name, double value, IDictionary<string, string> tags = null)
        {
            var m = new JObject { ["ts"] = Names.Now(), ["name"] = name, ["value"] = value };
            if (tags != null && tags.Count > 0) m["tags"] = JObject.FromObject(tags);
            lock (_gate) Enqueue(_metrics, m);
        }

        public void ReportEvent(string type, string message = "", EventLevel level = EventLevel.Info, IDictionary<string, object> data = null)
        {
            var e = new JObject { ["ts"] = Names.Now(), ["type"] = type, ["level"] = Names.Of(level), ["message"] = message ?? "" };
            if (data != null && data.Count > 0) e["data"] = JObject.FromObject(data);
            lock (_gate)
            {
                Enqueue(_events, e);
                if (level >= EventLevel.Error) _urgentEvent = true; // do not make an operator wait for a crash report
            }
        }

        /// <summary>Queues an error line from the host's log as an event, within the per-minute limit.</summary>
        public void ForwardError(string message, string stack)
        {
            lock (_gate)
            {
                var now = DateTime.UtcNow;
                while (_forwardedErrors.Count > 0 && now - _forwardedErrors.Peek() > TimeSpan.FromMinutes(1)) _forwardedErrors.Dequeue();
                if (_forwardedErrors.Count >= _o.MaxForwardedErrorsPerMinute) return;
                _forwardedErrors.Enqueue(now);
            }
            ReportEvent("app.error", Truncate(message, 300), EventLevel.Error,
                string.IsNullOrEmpty(stack) ? null : new Dictionary<string, object> { ["stack"] = Truncate(stack, 800) });
        }

        static void Enqueue(List<JObject> list, JObject item)
        {
            list.Add(item);
            if (list.Count > MaxQueued) list.RemoveRange(0, list.Count - MaxQueued);
        }

        static string Truncate(string s, int n) => string.IsNullOrEmpty(s) || s.Length <= n ? s ?? "" : s.Substring(0, n);

        // ------------------------------------------------------------ config

        void LoadFallbackFile()
        {
            if (string.IsNullOrEmpty(_o.ConfigFilePath)) return;
            var text = RemoteConfigOptions.ReadFileOrNull(_o.ConfigFilePath);
            if (text == null) return;
            if (ConfigDocument.TryParse(text, out var doc, out var err)) ApplyDocument(doc, ack: false);
            else _log("ignoring unreadable " + _o.ConfigFilePath + ": " + err);
        }

        async Task ConfigLoop(CancellationToken ct)
        {
            var backoff = new Backoff(TimeSpan.FromSeconds(1), TimeSpan.FromSeconds(30));
            while (!ct.IsCancellationRequested)
            {
                var headers = new Dictionary<string, string>();
                var etag = Config.Etag;
                if (etag.Length > 0) headers["If-None-Match"] = "\"" + etag + "\"";

                var started = DateTime.UtcNow;
                var r = await Send("GET", "/config?wait=" + _o.LongPollSeconds, null, headers, _o.LongPollSeconds + 10, ct);
                if (ct.IsCancellationRequested) return;

                if (r.NetworkError)
                {
                    Reachability(false);
                    if (!Config.HasConfig) LoadFallbackFile();
                    await Delay(backoff.Next(), ct);
                    continue;
                }
                Reachability(Accepted(r));

                switch (r.Status)
                {
                    case 200:
                        backoff.Reset();
                        if (ConfigDocument.TryParse(r.Body, out var doc, out var err)) ApplyDocument(doc, ack: true);
                        else _log("the agent sent a config we cannot read: " + err);
                        break;
                    case 304:
                        backoff.Reset();
                        // Nothing changed. A server that ignores ?wait= would make this a busy loop.
                        if (DateTime.UtcNow - started < TimeSpan.FromMilliseconds(500)) await Delay(TimeSpan.FromMilliseconds(500), ct);
                        break;
                    case 404: // the agent has no config for us yet
                        await Delay(TimeSpan.FromSeconds(2), ct);
                        break;
                    default: // 401 wrong token, 5xx...
                        _log($"GET /config -> HTTP {r.Status}");
                        await Delay(backoff.Next(), ct);
                        break;
                }
            }
        }

        void ApplyDocument(ConfigDocument doc, bool ack)
        {
            if (!Config.Apply(doc)) return; // the revision we already hold

            // One failing handler must not stop the others, and must not stop us telling the
            // agent the revision could not be applied.
            string error = null;
            var handlers = ConfigChanged;
            if (handlers != null)
            {
                foreach (var h in handlers.GetInvocationList())
                {
                    try { ((Action<ConfigDocument>)h)(doc); }
                    catch (Exception e)
                    {
                        error = error ?? e.Message;
                        _log("a ConfigChanged handler threw: " + e);
                    }
                }
            }
            if (ack) _ = AckAsync(doc.Revision, error);
        }

        async Task AckAsync(int revision, string error)
        {
            var body = new JObject { ["revision"] = revision, ["ok"] = error == null };
            if (error != null) body["error"] = Truncate(error, 300);
            await Send("POST", "/config/ack", body.ToString(Newtonsoft.Json.Formatting.None), null, 10, _cts.Token);
        }

        // ------------------------------------------------------------ heartbeat

        async Task HeartbeatLoop(CancellationToken ct)
        {
            var interval = TimeSpan.FromSeconds(Math.Max(0.1, _o.HeartbeatSeconds));
            while (!ct.IsCancellationRequested)
            {
                await SendHeartbeat(ct);
                await Delay(interval, ct);
            }
        }

        public Task SendHeartbeat(CancellationToken ct = default(CancellationToken))
        {
            AppState state;
            string message;
            Dictionary<string, object> custom;
            lock (_gate)
            {
                state = _state;
                message = _message;
                custom = new Dictionary<string, object>(_custom);
            }
            var body = HeartbeatBuilder.Build(state, message, _probe?.UptimeSeconds ?? 0, _o.BuildVersion,
                Config.Revision, _probe?.Fps ?? 0, custom);
            return SendHeartbeatBody(body, ct);
        }

        async Task SendHeartbeatBody(JObject body, CancellationToken ct)
        {
            var r = await Send("PUT", "/status", body.ToString(Newtonsoft.Json.Formatting.None), null, 10, ct);
            Reachability(Accepted(r));
        }

        /// <summary>The agent answered and let us in. A wrong token is "answering" but not "connected".</summary>
        static bool Accepted(TransportResponse r) => !r.NetworkError && r.Status != 401 && r.Status != 403;

        // ------------------------------------------------------------ lifecycle (quit hook)

        async Task LifecycleLoop(CancellationToken ct)
        {
            var backoff = new Backoff(TimeSpan.FromSeconds(1), TimeSpan.FromSeconds(30));
            bool raised = false; // the request stays pending until we exit; tell the app once
            while (!ct.IsCancellationRequested)
            {
                var started = DateTime.UtcNow;
                var r = await Send("GET", "/lifecycle?wait=" + _o.LongPollSeconds, null, null, _o.LongPollSeconds + 10, ct);
                if (ct.IsCancellationRequested) return;

                if (r.NetworkError)
                {
                    await Delay(backoff.Next(), ct);
                    continue;
                }
                backoff.Reset();

                if (r.Status == 200)
                {
                    JObject msg = null;
                    try { msg = JObject.Parse(r.Body); } catch (Exception) { /* treated as not a quit */ }
                    if ((string)msg?["action"] == "quit")
                    {
                        if (!raised)
                        {
                            raised = true;
                            LastQuitRequest = new QuitRequest((string)msg["reason"], (int?)msg["grace_s"] ?? 10);
                            RaiseQuit(LastQuitRequest);
                        }
                        await Delay(TimeSpan.FromSeconds(1), ct);
                        continue;
                    }
                }
                else if (r.Status == 204)
                {
                    raised = false;
                    if (DateTime.UtcNow - started < TimeSpan.FromMilliseconds(500)) await Delay(TimeSpan.FromMilliseconds(500), ct);
                }
                else
                {
                    await Delay(backoff.Next(), ct); // 401, 404 (a server without lifecycle), 5xx
                }
            }
        }

        void RaiseQuit(QuitRequest q)
        {
            var handlers = QuitRequested;
            if (handlers == null) return;
            foreach (var h in handlers.GetInvocationList())
            {
                try { ((Action<QuitRequest>)h)(q); }
                catch (Exception e) { _log("a QuitRequested handler threw: " + e); }
            }
        }

        // ------------------------------------------------------------ telemetry

        async Task TelemetryLoop(CancellationToken ct)
        {
            var lastEvents = DateTime.UtcNow;
            var lastMetrics = DateTime.UtcNow;
            while (!ct.IsCancellationRequested)
            {
                await Delay(TimeSpan.FromMilliseconds(500), ct);
                bool eventsDue, metricsDue;
                lock (_gate)
                {
                    var now = DateTime.UtcNow;
                    eventsDue = _events.Count > 0 && (_urgentEvent || _events.Count >= 50 || now - lastEvents > TimeSpan.FromSeconds(_o.EventBatchSeconds));
                    metricsDue = _metrics.Count > 0 && (_metrics.Count >= 100 || now - lastMetrics > TimeSpan.FromSeconds(_o.MetricBatchSeconds));
                }
                if (eventsDue) { await FlushList("/events", "events", _events, ct); lastEvents = DateTime.UtcNow; }
                if (metricsDue) { await FlushList("/metrics", "metrics", _metrics, ct); lastMetrics = DateTime.UtcNow; }
            }
        }

        /// <summary>Sends everything queued right now (events and metrics) instead of waiting for the batch timers.</summary>
        public async Task FlushAsync(CancellationToken ct = default(CancellationToken))
        {
            await FlushList("/events", "events", _events, ct);
            await FlushList("/metrics", "metrics", _metrics, ct);
        }

        async Task FlushList(string path, string key, List<JObject> list, CancellationToken ct)
        {
            JArray batch;
            lock (_gate)
            {
                if (list.Count == 0) return;
                batch = new JArray(list.GetRange(0, Math.Min(list.Count, 200)));
                list.RemoveRange(0, batch.Count);
                if (ReferenceEquals(list, _events)) _urgentEvent = false;
            }
            var r = await Send("POST", path, new JObject { [key] = batch }.ToString(Newtonsoft.Json.Formatting.None), null, 15, ct);
            if (r.NetworkError || r.Status / 100 != 2)
            {
                lock (_gate) // put them back (in front, in order) for the next attempt
                {
                    list.InsertRange(0, batch.Count > 0 ? batch.ToObject<List<JObject>>() : new List<JObject>());
                    if (list.Count > MaxQueued) list.RemoveRange(0, list.Count - MaxQueued);
                }
            }
        }

        // ------------------------------------------------------------ plumbing

        async Task<TransportResponse> Send(string method, string path, string body, IDictionary<string, string> headers, int timeout, CancellationToken ct)
        {
            try
            {
                var r = await _transport.SendAsync(method, path, body, headers, timeout, ct);
                if (!r.NetworkError) Interlocked.Exchange(ref _lastContactTicks, DateTime.UtcNow.Ticks);
                return r;
            }
            catch (OperationCanceledException) { return TransportResponse.Failure("cancelled"); }
            catch (Exception e) { return TransportResponse.Failure(e.Message); }
        }

        void Reachability(bool reachable)
        {
            if (_reachable == reachable) return;
            _reachable = reachable;
            _log(reachable ? "connected to the agent" : "not connected to the agent (unreachable, or it rejected our token); carrying on with the config we have");
        }

        static async Task Delay(TimeSpan d, CancellationToken ct)
        {
            try { await Task.Delay(d, ct); }
            catch (TaskCanceledException) { /* the caller checks the token */ }
        }
    }
}
