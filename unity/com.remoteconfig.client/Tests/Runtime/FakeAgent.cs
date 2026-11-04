using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Newtonsoft.Json.Linq;

namespace RemoteConfig.Tests
{
    /// <summary>
    /// A stand-in for the agent's local API with the behaviour the client relies on: config
    /// long-poll with ETags, status, acks, lifecycle long-poll, events and metrics.
    /// </summary>
    public sealed class FakeAgent : IDisposable
    {
        public const string Token = "test-token";

        readonly HttpListener _listener = new HttpListener();
        readonly CancellationTokenSource _cts = new CancellationTokenSource();
        readonly object _gate = new object();

        string _configJson;
        string _etag = "";
        bool _quit;
        string _quitReason = "";
        int _quitGrace;
        readonly List<JObject> _heartbeats = new List<JObject>();
        readonly List<JObject> _acks = new List<JObject>();
        readonly List<JObject> _events = new List<JObject>();
        readonly List<JObject> _metrics = new List<JObject>();
        int _configRequests;

        public string BaseUrl { get; }
        public int Port { get; }

        public FakeAgent(int port = 0)
        {
            if (port == 0)
            {
                var probe = new TcpListener(IPAddress.Loopback, 0);
                probe.Start();
                port = ((IPEndPoint)probe.LocalEndpoint).Port;
                probe.Stop();
            }
            Port = port;
            BaseUrl = $"http://127.0.0.1:{port}/v1";
            _listener.Prefixes.Add($"http://127.0.0.1:{port}/v1/");
            _listener.Start();
            _ = Task.Run(AcceptLoop);
        }

        // ------------------------------------------------------------ what a test sets

        /// <summary>Publishes a config revision. The ETag defaults to one derived from the revision.</summary>
        public void SetConfig(int revision, object data, string etag = null, string reloadMode = "watch")
        {
            var json = new JObject
            {
                ["revision"] = revision,
                ["etag"] = etag ?? ("etag-" + revision),
                ["reload_mode"] = reloadMode,
                ["data"] = JObject.FromObject(data),
            };
            lock (_gate)
            {
                _configJson = json.ToString();
                _etag = (string)json["etag"];
            }
        }

        public void RequestQuit(string reason, int graceSeconds)
        {
            lock (_gate)
            {
                _quit = true;
                _quitReason = reason;
                _quitGrace = graceSeconds;
            }
        }

        public void ClearQuit() { lock (_gate) _quit = false; }

        // ------------------------------------------------------------ what a test checks

        public List<JObject> Heartbeats { get { lock (_gate) return new List<JObject>(_heartbeats); } }
        public List<JObject> Acks { get { lock (_gate) return new List<JObject>(_acks); } }
        public List<JObject> Events { get { lock (_gate) return new List<JObject>(_events); } }
        public List<JObject> Metrics { get { lock (_gate) return new List<JObject>(_metrics); } }
        public int ConfigRequests { get { lock (_gate) return _configRequests; } }

        public void Dispose()
        {
            _cts.Cancel();
            try { _listener.Stop(); _listener.Close(); } catch (Exception) { }
        }

        // ------------------------------------------------------------ server

        async Task AcceptLoop()
        {
            while (!_cts.IsCancellationRequested)
            {
                HttpListenerContext ctx;
                try { ctx = await _listener.GetContextAsync(); }
                catch (Exception) { return; }
                _ = Task.Run(() => Handle(ctx));
            }
        }

        async Task Handle(HttpListenerContext ctx)
        {
            try
            {
                var req = ctx.Request;
                if (req.Headers["Authorization"] != "Bearer " + Token)
                {
                    Respond(ctx, 401, "{\"error\":\"invalid local token\"}");
                    return;
                }
                var path = req.Url.AbsolutePath;
                var wait = int.TryParse(req.QueryString["wait"], out var w) ? Math.Min(w, 60) : 0;

                switch (req.HttpMethod + " " + path)
                {
                    case "GET /v1/config": await ServeConfig(ctx, wait); break;
                    case "GET /v1/lifecycle": await ServeLifecycle(ctx, wait); break;
                    case "PUT /v1/status": Record(ctx, _heartbeats, null); Respond(ctx, 204, null); break;
                    case "POST /v1/config/ack": Record(ctx, _acks, null); Respond(ctx, 204, null); break;
                    case "POST /v1/events": Record(ctx, _events, "events"); Respond(ctx, 202, null); break;
                    case "POST /v1/metrics": Record(ctx, _metrics, "metrics"); Respond(ctx, 202, null); break;
                    default: Respond(ctx, 404, "{\"error\":\"not found\"}"); break;
                }
            }
            catch (Exception)
            {
                try { ctx.Response.Abort(); } catch (Exception) { }
            }
        }

        async Task ServeConfig(HttpListenerContext ctx, int wait)
        {
            lock (_gate) _configRequests++;
            var clientEtag = (ctx.Request.Headers["If-None-Match"] ?? "").Trim('"');
            var deadline = DateTime.UtcNow.AddSeconds(wait);
            while (true)
            {
                string json, etag;
                lock (_gate) { json = _configJson; etag = _etag; }
                if (json == null) { Respond(ctx, 404, "{\"error\":\"no config yet\"}"); return; }
                if (etag != clientEtag)
                {
                    ctx.Response.Headers["ETag"] = "\"" + etag + "\"";
                    Respond(ctx, 200, json);
                    return;
                }
                if (DateTime.UtcNow >= deadline || _cts.IsCancellationRequested) { Respond(ctx, 304, null); return; }
                await Task.Delay(30);
            }
        }

        async Task ServeLifecycle(HttpListenerContext ctx, int wait)
        {
            var deadline = DateTime.UtcNow.AddSeconds(wait);
            while (true)
            {
                bool quit; string reason; int grace;
                lock (_gate) { quit = _quit; reason = _quitReason; grace = _quitGrace; }
                if (quit)
                {
                    Respond(ctx, 200, new JObject { ["action"] = "quit", ["reason"] = reason, ["grace_s"] = grace }.ToString());
                    return;
                }
                if (DateTime.UtcNow >= deadline || _cts.IsCancellationRequested) { Respond(ctx, 204, null); return; }
                await Task.Delay(30);
            }
        }

        void Record(HttpListenerContext ctx, List<JObject> into, string arrayKey)
        {
            string body;
            using (var r = new StreamReader(ctx.Request.InputStream, Encoding.UTF8)) body = r.ReadToEnd();
            var obj = JObject.Parse(body);
            lock (_gate)
            {
                if (arrayKey == null) into.Add(obj);
                else foreach (var item in (JArray)obj[arrayKey]) into.Add((JObject)item);
            }
        }

        static void Respond(HttpListenerContext ctx, int status, string body)
        {
            ctx.Response.StatusCode = status;
            if (body != null)
            {
                var bytes = Encoding.UTF8.GetBytes(body);
                ctx.Response.ContentType = "application/json";
                ctx.Response.ContentLength64 = bytes.Length;
                ctx.Response.OutputStream.Write(bytes, 0, bytes.Length);
            }
            ctx.Response.Close();
        }
    }
}
