using System;
using System.Collections.Generic;
using System.IO;

namespace RemoteConfig
{
    /// <summary>
    /// Where the agent is and how the client behaves. When the app is launched by the agent
    /// (the normal case) the agent puts everything in environment variables and
    /// <see cref="FromEnvironment"/> needs no further setup.
    /// </summary>
    public sealed class RemoteConfigOptions
    {
        /// <summary>Set by the agent in the app's environment. Includes the /v1 prefix.</summary>
        public const string EnvUrl = "REMOTECONFIG_URL";
        public const string EnvToken = "REMOTECONFIG_TOKEN";
        public const string EnvConfigFile = "REMOTECONFIG_CONFIG_FILE";

        public const string DefaultUrl = "http://127.0.0.1:7878/v1";

        /// <summary>Agent (or server) API root, e.g. http://127.0.0.1:7878/v1.</summary>
        public string BaseUrl = "";

        /// <summary>Bearer token: the agent's local token, or a device/API key when talking to the server.</summary>
        public string Token = "";

        /// <summary>
        /// The effective-config.json the agent keeps on disk. Used so the app has its last
        /// known config at startup, and whenever the agent cannot be reached.
        /// </summary>
        public string ConfigFilePath = "";

        public float HeartbeatSeconds = 10f;

        /// <summary>How long config and lifecycle requests wait on the agent for a change.</summary>
        public int LongPollSeconds = 30;

        /// <summary>Events wait at most this long to be batched with others (errors go out at once).</summary>
        public float EventBatchSeconds = 10f;

        /// <summary>Metrics wait at most this long to be batched with others.</summary>
        public float MetricBatchSeconds = 30f;

        public string BuildVersion = "";

        /// <summary>Call Application.Quit() when the agent asks the app to shut down.</summary>
        public bool QuitWhenAsked = true;

        /// <summary>Send Debug.LogError / exceptions to the dashboard as events.</summary>
        public bool ForwardErrors = true;

        public int MaxForwardedErrorsPerMinute = 20;

        public bool IsUsable => !string.IsNullOrEmpty(BaseUrl);

        /// <summary>Reads REMOTECONFIG_URL / _TOKEN / _CONFIG_FILE. Leaves fields empty if unset.</summary>
        public static RemoteConfigOptions FromEnvironment(Func<string, string> getenv = null)
        {
            getenv = getenv ?? Environment.GetEnvironmentVariable;
            return new RemoteConfigOptions
            {
                BaseUrl = getenv(EnvUrl) ?? "",
                Token = getenv(EnvToken) ?? "",
                ConfigFilePath = getenv(EnvConfigFile) ?? "",
            };
        }

        /// <summary>
        /// For an app started by hand (so there are no environment variables): fall back to
        /// the agent's default address and read its token from where the agent keeps it.
        /// Anything already set is left alone.
        /// </summary>
        public RemoteConfigOptions FillMissingDefaults(Func<string, string> getenv = null, Func<string, string> readFile = null)
        {
            getenv = getenv ?? Environment.GetEnvironmentVariable;
            readFile = readFile ?? ReadFileOrNull;

            if (string.IsNullOrEmpty(BaseUrl)) BaseUrl = DefaultUrl;
            if (string.IsNullOrEmpty(Token))
            {
                foreach (var dir in CandidateStateDirs(getenv))
                {
                    var token = readFile(Path.Combine(dir, "local-token"));
                    if (string.IsNullOrWhiteSpace(token)) continue;
                    Token = token.Trim();
                    if (string.IsNullOrEmpty(ConfigFilePath)) ConfigFilePath = Path.Combine(dir, "effective-config.json");
                    break;
                }
            }
            return this;
        }

        /// <summary>The agent's state directory: where an installed agent keeps it, then the per-user default.</summary>
        internal static IEnumerable<string> CandidateStateDirs(Func<string, string> getenv)
        {
            var programData = getenv("ProgramData");
            if (!string.IsNullOrEmpty(programData)) yield return Path.Combine(programData, "RemoteConfig", "state");
            var appData = getenv("APPDATA");
            if (!string.IsNullOrEmpty(appData)) yield return Path.Combine(appData, "RemoteConfig");
            var home = getenv("HOME");
            if (!string.IsNullOrEmpty(home)) yield return Path.Combine(home, ".config", "RemoteConfig");
        }

        internal static string ReadFileOrNull(string path)
        {
            try { return File.Exists(path) ? File.ReadAllText(path) : null; }
            catch (Exception) { return null; }
        }
    }
}
