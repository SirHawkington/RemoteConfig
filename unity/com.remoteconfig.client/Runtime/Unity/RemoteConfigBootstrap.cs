#if !REMOTECONFIG_NO_AUTOSTART
using System;
using UnityEngine;

namespace RemoteConfig
{
    /// <summary>
    /// Starts the client by itself when the app was launched by the agent, which is recognisable
    /// by the REMOTECONFIG_URL it sets. So a built player gains heartbeat, live config and the
    /// quit hook with no scene changes. In the editor, or when started by hand, nothing happens
    /// unless you add the component or call <see cref="RemoteConfigClient.Create"/>.
    ///
    /// Define REMOTECONFIG_NO_AUTOSTART in Player Settings to turn this off.
    /// </summary>
    static class RemoteConfigBootstrap
    {
        [RuntimeInitializeOnLoadMethod(RuntimeInitializeLoadType.AfterSceneLoad)]
        static void AutoStart()
        {
            if (RemoteConfigClient.Instance != null) return; // the scene has its own
            if (string.IsNullOrEmpty(Environment.GetEnvironmentVariable(RemoteConfigOptions.EnvUrl))) return;
            new GameObject("RemoteConfig (auto)").AddComponent<RemoteConfigClient>();
        }
    }
}
#endif
