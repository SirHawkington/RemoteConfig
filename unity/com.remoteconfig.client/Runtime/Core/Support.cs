using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Newtonsoft.Json.Linq;

namespace RemoteConfig
{
    public sealed class TransportResponse
    {
        /// <summary>HTTP status, or 0 when no response was received at all.</summary>
        public int Status;
        public string Body = "";
        public bool NetworkError;
        public string Error = "";

        public static TransportResponse Failure(string error) => new TransportResponse { NetworkError = true, Error = error };
    }

    /// <summary>How requests reach the agent. Unity uses UnityWebRequest; tests can use anything.</summary>
    public interface IRemoteTransport
    {
        Task<TransportResponse> SendAsync(string method, string path, string jsonBody,
            IDictionary<string, string> headers, int timeoutSeconds, CancellationToken ct);
    }

    /// <summary>Retry delays that double up to a ceiling.</summary>
    public sealed class Backoff
    {
        readonly TimeSpan _min, _max;
        int _attempts;

        public Backoff(TimeSpan min, TimeSpan max)
        {
            _min = min;
            _max = max;
        }

        public TimeSpan Next()
        {
            var ticks = _min.Ticks << Math.Min(_attempts, 20);
            _attempts++;
            return TimeSpan.FromTicks(Math.Min(_max.Ticks, ticks));
        }

        public void Reset() => _attempts = 0;
    }

    /// <summary>Builds the PUT /status body.</summary>
    public static class HeartbeatBuilder
    {
        public static JObject Build(AppState state, string message, double uptimeSeconds, string build,
            int configRevision, double fps, IDictionary<string, object> custom)
        {
            var o = new JObject
            {
                ["state"] = Names.Of(state),
                ["uptime_s"] = (long)uptimeSeconds,
                ["build"] = build ?? "",
                ["config_revision"] = configRevision,
            };
            if (fps > 0) o["fps"] = Math.Round(fps, 1);
            if (!string.IsNullOrEmpty(message)) o["message"] = message.Length > 250 ? message.Substring(0, 250) : message;
            if (custom != null && custom.Count > 0)
            {
                var m = new JObject();
                foreach (var kv in custom) m[kv.Key] = kv.Value == null ? JValue.CreateNull() : JToken.FromObject(kv.Value);
                o["metrics"] = m;
            }
            return o;
        }
    }
}
