using System;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace RemoteConfig
{
    /// <summary>One revision of the effective config, as served by the agent.</summary>
    public sealed class ConfigDocument
    {
        public int Revision;
        public string Etag = "";

        /// <summary>none | watch | trigger | restart: how the operator expects the app to react.</summary>
        public string ReloadMode = "watch";

        /// <summary>Your app's settings: the "data" object of the config.</summary>
        public JObject Data = new JObject();

        public static bool TryParse(string json, out ConfigDocument doc, out string error)
        {
            doc = null;
            error = null;
            try
            {
                var root = JObject.Parse(json);
                var data = root["data"] as JObject;
                if (data == null)
                {
                    error = "the config has no \"data\" object";
                    return false;
                }
                doc = new ConfigDocument
                {
                    Revision = (int?)root["revision"] ?? 0,
                    Etag = (string)root["etag"] ?? "",
                    ReloadMode = (string)root["reload_mode"] ?? "watch",
                    Data = data,
                };
                return true;
            }
            catch (JsonException e)
            {
                error = e.Message;
                return false;
            }
        }
    }

    /// <summary>Holds the current config and answers typed lookups by path ("ui.language", "items[0].name").</summary>
    public sealed class ConfigStore
    {
        readonly object _gate = new object();
        ConfigDocument _current;

        public ConfigDocument Current { get { lock (_gate) return _current; } }
        public int Revision => Current?.Revision ?? 0;
        public string Etag => Current?.Etag ?? "";
        public bool HasConfig => Current != null;

        /// <summary>Makes <paramref name="doc"/> current. Returns false (and changes nothing) if it is the one already held.</summary>
        public bool Apply(ConfigDocument doc)
        {
            lock (_gate)
            {
                if (_current != null && doc.Etag.Length > 0 && doc.Etag == _current.Etag) return false;
                _current = doc;
                return true;
            }
        }

        public bool TryGet<T>(string path, out T value)
        {
            value = default(T);
            var doc = Current;
            if (doc == null) return false;
            try
            {
                var token = doc.Data.SelectToken(path);
                if (token == null || token.Type == JTokenType.Null) return false;
                value = token.ToObject<T>();
                return true;
            }
            catch (Exception) // wrong type or malformed path: behave as "not there"
            {
                value = default(T);
                return false;
            }
        }

        public T Get<T>(string path, T fallback = default(T)) => TryGet(path, out T v) ? v : fallback;
    }
}
