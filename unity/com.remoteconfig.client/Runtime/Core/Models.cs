using System;

namespace RemoteConfig
{
    /// <summary>What the app reports about itself in every heartbeat.</summary>
    public enum AppState
    {
        Loading,
        Running,
        Idle,
        Error,
    }

    public enum EventLevel
    {
        Debug,
        Info,
        Warn,
        Error,
    }

    /// <summary>The agent wants the app to shut down (restart, scheduled restart, config change...).</summary>
    public sealed class QuitRequest
    {
        public string Reason { get; }

        /// <summary>Seconds the app has to save and exit before the agent kills it.</summary>
        public int GraceSeconds { get; }

        public QuitRequest(string reason, int graceSeconds)
        {
            Reason = reason ?? "";
            GraceSeconds = graceSeconds;
        }

        public override string ToString() => $"quit requested: {Reason} ({GraceSeconds}s)";
    }

    /// <summary>Supplies facts about the running app that only the host (Unity) knows.</summary>
    public interface IAppProbe
    {
        double Fps { get; }
        double UptimeSeconds { get; }
    }

    internal static class Names
    {
        public static string Of(AppState s)
        {
            switch (s)
            {
                case AppState.Loading: return "loading";
                case AppState.Idle: return "idle";
                case AppState.Error: return "error";
                default: return "running";
            }
        }

        public static string Of(EventLevel l)
        {
            switch (l)
            {
                case EventLevel.Debug: return "debug";
                case EventLevel.Warn: return "warn";
                case EventLevel.Error: return "error";
                default: return "info";
            }
        }

        public static string Now() => DateTime.UtcNow.ToString("o", System.Globalization.CultureInfo.InvariantCulture);
    }
}
