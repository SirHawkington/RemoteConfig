using System;
using System.Collections.Generic;
using System.IO;
using NUnit.Framework;
using Newtonsoft.Json.Linq;

namespace RemoteConfig.Tests
{
    public class ConfigDocumentTests
    {
        const string Good = "{\"revision\":4,\"etag\":\"abc\",\"reload_mode\":\"restart\",\"data\":{\"volume\":0.5}}";

        [Test]
        public void ParsesTheAgentsEnvelope()
        {
            Assert.IsTrue(ConfigDocument.TryParse(Good, out var doc, out var err), err);
            Assert.AreEqual(4, doc.Revision);
            Assert.AreEqual("abc", doc.Etag);
            Assert.AreEqual("restart", doc.ReloadMode);
            Assert.AreEqual(0.5, (double)doc.Data["volume"], 1e-9);
        }

        [Test]
        public void DefaultsWhenOptionalFieldsAreMissing()
        {
            Assert.IsTrue(ConfigDocument.TryParse("{\"data\":{}}", out var doc, out _));
            Assert.AreEqual(0, doc.Revision);
            Assert.AreEqual("", doc.Etag);
            Assert.AreEqual("watch", doc.ReloadMode);
        }

        [TestCase("not json")]
        [TestCase("{\"revision\":1}")]
        [TestCase("{\"data\":[1,2]}")]
        [TestCase("")]
        public void RejectsWhatIsNotAConfig(string json)
        {
            Assert.IsFalse(ConfigDocument.TryParse(json, out var doc, out var err));
            Assert.IsNull(doc);
            Assert.IsNotEmpty(err);
        }
    }

    public class ConfigStoreTests
    {
        static ConfigDocument Doc(string etag, string dataJson, int rev = 1) => new ConfigDocument
        {
            Revision = rev,
            Etag = etag,
            Data = JObject.Parse(dataJson),
        };

        [Test]
        public void TypedLookupsByPath()
        {
            var s = new ConfigStore();
            s.Apply(Doc("e", "{\"audio\":{\"volume\":0.8,\"mute\":false},\"items\":[{\"name\":\"a\"},{\"name\":\"b\"}],\"title\":\"Hi\",\"count\":3}"));
            Assert.AreEqual(0.8f, s.Get("audio.volume", 0f), 1e-6);
            Assert.IsFalse(s.Get("audio.mute", true));
            Assert.AreEqual("b", s.Get("items[1].name", ""));
            Assert.AreEqual("Hi", s.Get<string>("title"));
            Assert.AreEqual(3, s.Get("count", 0));
            Assert.AreEqual(3.0, s.Get("count", 0.0), 1e-9, "an integer reads as a double");
        }

        [Test]
        public void MissingOrMistypedValuesGiveTheFallbackInsteadOfThrowing()
        {
            var s = new ConfigStore();
            Assert.AreEqual(7, s.Get("anything", 7), "no config yet");
            s.Apply(Doc("e", "{\"name\":\"x\",\"nothing\":null,\"n\":5}"));
            Assert.AreEqual(7, s.Get("missing", 7));
            Assert.AreEqual(7, s.Get("name", 7), "a string is not an int");
            Assert.AreEqual(7, s.Get("nothing", 7), "null counts as not set");
            Assert.AreEqual(7, s.Get("a..b[", 7), "a malformed path is not an error");
            Assert.IsFalse(s.TryGet("missing", out int _));
            Assert.IsTrue(s.TryGet("n", out int n) && n == 5);
        }

        [Test]
        public void ApplyIgnoresARevisionItAlreadyHolds()
        {
            var s = new ConfigStore();
            Assert.IsTrue(s.Apply(Doc("e1", "{\"v\":1}", 1)));
            Assert.IsFalse(s.Apply(Doc("e1", "{\"v\":1}", 1)), "same etag: nothing changed");
            Assert.IsTrue(s.Apply(Doc("e2", "{\"v\":2}", 2)));
            Assert.AreEqual(2, s.Revision);
            Assert.AreEqual(2, s.Get("v", 0));
        }

        [Test]
        public void DocumentsWithoutAnEtagAreAlwaysApplied()
        {
            var s = new ConfigStore();
            Assert.IsTrue(s.Apply(Doc("", "{\"v\":1}")));
            Assert.IsTrue(s.Apply(Doc("", "{\"v\":2}")));
        }
    }

    public class OptionsTests
    {
        static Func<string, string> Env(Dictionary<string, string> vars) => k => vars.TryGetValue(k, out var v) ? v : null;

        [Test]
        public void ReadsWhatTheAgentPutsInTheEnvironment()
        {
            var o = RemoteConfigOptions.FromEnvironment(Env(new Dictionary<string, string>
            {
                ["REMOTECONFIG_URL"] = "http://127.0.0.1:7878/v1",
                ["REMOTECONFIG_TOKEN"] = "secret",
                ["REMOTECONFIG_CONFIG_FILE"] = @"C:\state\effective-config.json",
            }));
            Assert.AreEqual("http://127.0.0.1:7878/v1", o.BaseUrl);
            Assert.AreEqual("secret", o.Token);
            Assert.AreEqual(@"C:\state\effective-config.json", o.ConfigFilePath);
            Assert.IsTrue(o.IsUsable);
        }

        [Test]
        public void AnAppStartedByHandFindsTheAgentsTokenFile()
        {
            var env = Env(new Dictionary<string, string> { ["ProgramData"] = @"C:\PD", ["APPDATA"] = @"C:\AD" });
            var files = new Dictionary<string, string> { [Path.Combine(@"C:\AD", "RemoteConfig", "local-token")] = "  tok123\n" };
            var o = new RemoteConfigOptions().FillMissingDefaults(env, p => files.TryGetValue(p, out var t) ? t : null);
            Assert.AreEqual(RemoteConfigOptions.DefaultUrl, o.BaseUrl);
            Assert.AreEqual("tok123", o.Token);
            Assert.AreEqual(Path.Combine(@"C:\AD", "RemoteConfig", "effective-config.json"), o.ConfigFilePath);
        }

        [Test]
        public void AnInstalledAgentsStateFolderWinsOverThePerUserOne()
        {
            var env = Env(new Dictionary<string, string> { ["ProgramData"] = @"C:\PD", ["APPDATA"] = @"C:\AD" });
            var files = new Dictionary<string, string>
            {
                [Path.Combine(@"C:\PD", "RemoteConfig", "state", "local-token")] = "installed",
                [Path.Combine(@"C:\AD", "RemoteConfig", "local-token")] = "peruser",
            };
            var o = new RemoteConfigOptions().FillMissingDefaults(env, p => files.TryGetValue(p, out var t) ? t : null);
            Assert.AreEqual("installed", o.Token);
        }

        [Test]
        public void ExplicitSettingsAreNotOverwritten()
        {
            var o = new RemoteConfigOptions { BaseUrl = "http://x/v1", Token = "mine", ConfigFilePath = "f.json" };
            o.FillMissingDefaults(Env(new Dictionary<string, string> { ["APPDATA"] = @"C:\AD" }), _ => "other");
            Assert.AreEqual("http://x/v1", o.BaseUrl);
            Assert.AreEqual("mine", o.Token);
            Assert.AreEqual("f.json", o.ConfigFilePath);
        }
    }

    public class SupportTests
    {
        [Test]
        public void BackoffDoublesUpToTheCeilingAndResets()
        {
            var b = new Backoff(TimeSpan.FromSeconds(1), TimeSpan.FromSeconds(10));
            var seen = new List<double>();
            for (var i = 0; i < 6; i++) seen.Add(b.Next().TotalSeconds);
            CollectionAssert.AreEqual(new[] { 1.0, 2.0, 4.0, 8.0, 10.0, 10.0 }, seen);
            b.Reset();
            Assert.AreEqual(1.0, b.Next().TotalSeconds);
        }

        [Test]
        public void BackoffDoesNotOverflowAfterManyFailures()
        {
            var b = new Backoff(TimeSpan.FromSeconds(1), TimeSpan.FromSeconds(30));
            for (var i = 0; i < 500; i++) Assert.LessOrEqual(b.Next().TotalSeconds, 30);
        }

        [Test]
        public void HeartbeatHasTheShapeTheAgentExpects()
        {
            var hb = HeartbeatBuilder.Build(AppState.Loading, "warming up", 123.9, "1.2.3", 7, 59.96,
                new Dictionary<string, object> { ["scene"] = "Lobby", ["visitors"] = 4, ["ok"] = true });
            Assert.AreEqual("loading", (string)hb["state"]);
            Assert.AreEqual(123, (long)hb["uptime_s"]);
            Assert.AreEqual("1.2.3", (string)hb["build"]);
            Assert.AreEqual(7, (int)hb["config_revision"]);
            Assert.AreEqual(60.0, (double)hb["fps"], 1e-9);
            Assert.AreEqual("warming up", (string)hb["message"]);
            Assert.AreEqual("Lobby", (string)hb["metrics"]["scene"]);
            Assert.AreEqual(4, (int)hb["metrics"]["visitors"]);
            Assert.AreEqual(true, (bool)hb["metrics"]["ok"]);
        }

        [Test]
        public void HeartbeatOmitsWhatItDoesNotHaveAndTrimsLongMessages()
        {
            var hb = HeartbeatBuilder.Build(AppState.Error, new string('x', 1000), 0, null, 0, 0, null);
            Assert.AreEqual("error", (string)hb["state"]);
            Assert.IsNull(hb["fps"]);
            Assert.IsNull(hb["metrics"]);
            Assert.LessOrEqual(((string)hb["message"]).Length, 256, "the agent rejects messages over 256 characters");
        }

        [TestCase(AppState.Loading, "loading")]
        [TestCase(AppState.Running, "running")]
        [TestCase(AppState.Idle, "idle")]
        [TestCase(AppState.Error, "error")]
        public void StateNamesMatchTheApi(AppState state, string name)
        {
            Assert.AreEqual(name, (string)HeartbeatBuilder.Build(state, null, 0, "", 0, 0, null)["state"]);
        }
    }
}
