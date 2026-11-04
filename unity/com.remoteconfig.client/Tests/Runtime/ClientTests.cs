using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using NUnit.Framework;
using Newtonsoft.Json.Linq;
using UnityEngine;
using UnityEngine.TestTools;

namespace RemoteConfig.Tests
{
    /// <summary>The real client, in Unity, against a fake agent.</summary>
    public class ClientTests
    {
        FakeAgent _agent;
        RemoteConfigClient _client;
        string _tempDir;

        [SetUp]
        public void SetUp()
        {
            _agent = new FakeAgent();
            _tempDir = Path.Combine(Path.GetTempPath(), "rc-client-tests-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(_tempDir);
        }

        [TearDown]
        public void TearDown()
        {
            if (_client != null) UnityEngine.Object.Destroy(_client.gameObject);
            _client = null;
            _agent?.Dispose();
            try { Directory.Delete(_tempDir, true); } catch (Exception) { }
        }

        RemoteConfigOptions Options(Action<RemoteConfigOptions> tweak = null)
        {
            var o = new RemoteConfigOptions
            {
                BaseUrl = _agent.BaseUrl,
                Token = FakeAgent.Token,
                HeartbeatSeconds = 0.2f,
                LongPollSeconds = 2,
                QuitWhenAsked = false, // a test runner that quits itself is not much use
                ForwardErrors = false,
                BuildVersion = "9.9.9",
                EventBatchSeconds = 1f,
                MetricBatchSeconds = 1f,
            };
            tweak?.Invoke(o);
            return o;
        }

        RemoteConfigClient StartClient(Action<RemoteConfigOptions> tweak = null)
        {
            _client = RemoteConfigClient.Create(Options(tweak), persistAcrossScenes: false);
            return _client;
        }

        static IEnumerator WaitFor(Func<bool> condition, string what, float timeoutSeconds = 10f)
        {
            var start = Time.realtimeSinceStartup;
            while (!condition())
            {
                if (Time.realtimeSinceStartup - start > timeoutSeconds) Assert.Fail("timed out waiting for " + what);
                yield return null;
            }
        }

        // ---------------------------------------------------------------- heartbeat

        [UnityTest]
        public IEnumerator HeartbeatIsSentRepeatedlyWithStateBuildAndRevision()
        {
            _agent.SetConfig(3, new { a = 1 });
            StartClient();
            yield return WaitFor(() => _agent.Heartbeats.Count >= 3, "three heartbeats");

            var last = _agent.Heartbeats.Last();
            Assert.AreEqual("running", (string)last["state"]);
            Assert.AreEqual("9.9.9", (string)last["build"]);
            Assert.GreaterOrEqual((long)last["uptime_s"], 0);
            yield return WaitFor(() => (int)_agent.Heartbeats.Last()["config_revision"] == 3, "the heartbeat to report config revision 3");
        }

        [UnityTest]
        public IEnumerator StateAndStatusRideAlongWithTheHeartbeat()
        {
            StartClient();
            _client.SetState(AppState.Loading, "loading the lobby");
            _client.SetStatus("scene", "Lobby");
            yield return WaitFor(() => _agent.Heartbeats.Any(h => (string)h["state"] == "loading"), "a loading heartbeat");

            var hb = _agent.Heartbeats.Last(h => (string)h["state"] == "loading");
            Assert.AreEqual("loading the lobby", (string)hb["message"]);
            Assert.AreEqual("Lobby", (string)hb["metrics"]["scene"]);

            _client.SetState(AppState.Running);
            _client.SetStatus("scene", null);
            yield return WaitFor(() => { var l = _agent.Heartbeats.Last(); return (string)l["state"] == "running" && l["metrics"] == null; }, "the status to clear");
        }

        // ---------------------------------------------------------------- config hot reload

        [UnityTest]
        public IEnumerator ConfigArrivesRaisesTheEventAndIsAcknowledged()
        {
            _agent.SetConfig(1, new { volume = 0.5, ui = new { language = "en" } });
            var seen = new List<ConfigDocument>();
            StartClient();
            _client.ConfigChanged += d => seen.Add(d);

            yield return WaitFor(() => seen.Count == 1, "the first config");
            Assert.AreEqual(1, seen[0].Revision);
            Assert.AreEqual(0.5f, RemoteConfigClient.Get("volume", 0f), 1e-6);
            Assert.AreEqual("en", RemoteConfigClient.Get("ui.language", ""));
            yield return WaitFor(() => _agent.Acks.Any(a => (int)a["revision"] == 1 && (bool)a["ok"]), "an ack for revision 1");
        }

        [UnityTest]
        public IEnumerator ANewRevisionHotReloadsWithoutRestartingAnything()
        {
            _agent.SetConfig(1, new { volume = 0.5 });
            var seen = new List<ConfigDocument>();
            StartClient();
            _client.ConfigChanged += d => seen.Add(d);
            yield return WaitFor(() => seen.Count == 1, "revision 1");

            _agent.SetConfig(2, new { volume = 0.9, extra = "yes" });
            yield return WaitFor(() => seen.Count == 2, "revision 2 within the long-poll", 6f);

            Assert.AreEqual(2, seen[1].Revision);
            Assert.AreEqual(0.9f, RemoteConfigClient.Get("volume", 0f), 1e-6);
            Assert.AreEqual("yes", RemoteConfigClient.Get("extra", ""));
            Assert.AreEqual(2, _client.ConfigRevision);
            yield return WaitFor(() => _agent.Acks.Any(a => (int)a["revision"] == 2), "an ack for revision 2");
        }

        [UnityTest]
        public IEnumerator AnUnchangedRevisionDoesNotFireAgain()
        {
            _agent.SetConfig(1, new { v = 1 });
            var fired = 0;
            StartClient();
            _client.ConfigChanged += _ => fired++;
            yield return WaitFor(() => fired == 1, "the first config");

            var requests = _agent.ConfigRequests;
            yield return WaitFor(() => _agent.ConfigRequests > requests, "another long-poll round trip", 8f); // 304s, same etag
            Assert.AreEqual(1, fired);
        }

        [UnityTest]
        public IEnumerator OnConfigCallsTheHandlerImmediatelyOnceAConfigIsHeld()
        {
            _agent.SetConfig(1, new { title = "Hello" });
            StartClient();
            yield return WaitFor(() => _client.ConfigRevision == 1, "the config");

            string got = null;
            var unsubscribe = RemoteConfigClient.OnConfig(d => got = RemoteConfigClient.Get("title", ""));
            Assert.AreEqual("Hello", got, "a late subscriber must not have to wait for the next change");

            got = null;
            unsubscribe();
            _agent.SetConfig(2, new { title = "Bye" });
            yield return WaitFor(() => _client.ConfigRevision == 2, "revision 2", 6f);
            Assert.IsNull(got, "an unsubscribed handler is not called");
        }

        [UnityTest]
        public IEnumerator AHandlerThatThrowsIsReportedAsAFailedApply()
        {
            _agent.SetConfig(1, new { v = 1 });
            StartClient();
            var otherHandlerRan = false;
            _client.ConfigChanged += _ => throw new InvalidOperationException("bad config for this app");
            _client.ConfigChanged += _ => otherHandlerRan = true;
            LogAssert.Expect(LogType.Exception, new System.Text.RegularExpressions.Regex("bad config for this app")); // logged for the developer

            yield return WaitFor(() => _agent.Acks.Count > 0, "an ack");
            var ack = _agent.Acks[0];
            Assert.IsFalse((bool)ack["ok"]);
            StringAssert.Contains("bad config for this app", (string)ack["error"]);
            Assert.IsTrue(otherHandlerRan, "one broken handler must not starve the others");
        }

        [UnityTest]
        public IEnumerator TheOnDiskConfigIsUsedBeforeTheAgentAnswers()
        {
            var file = Path.Combine(_tempDir, "effective-config.json");
            File.WriteAllText(file, "{\"revision\":5,\"etag\":\"disk\",\"data\":{\"mode\":\"from-disk\"}}");
            StartClient(o => o.ConfigFilePath = file); // the fake agent has no config: it answers 404

            Assert.AreEqual(5, _client.ConfigRevision, "available straight away, in Awake");
            Assert.AreEqual("from-disk", RemoteConfigClient.Get("mode", ""));
            yield return null;
        }

        [UnityTest]
        public IEnumerator AgentDownAtStartIsSurvivedAndRecoveredFrom()
        {
            var port = _agent.Port;
            _agent.Dispose();
            var file = Path.Combine(_tempDir, "effective-config.json");
            File.WriteAllText(file, "{\"revision\":2,\"etag\":\"disk\",\"data\":{\"from\":\"disk\"}}");
            _client = RemoteConfigClient.Create(new RemoteConfigOptions
            {
                BaseUrl = $"http://127.0.0.1:{port}/v1", Token = FakeAgent.Token, ConfigFilePath = file,
                HeartbeatSeconds = 0.2f, LongPollSeconds = 2, QuitWhenAsked = false, ForwardErrors = false,
            }, false);

            yield return new WaitForSecondsRealtime(1.2f);
            Assert.IsFalse(_client.IsConnected);
            Assert.AreEqual("disk", RemoteConfigClient.Get("from", ""), "keeps working on the last known config");

            _agent = new FakeAgent(port); // the agent comes back
            _agent.SetConfig(3, new { from = "agent" });
            yield return WaitFor(() => _client.IsConnected, "the client to find the agent again", 15f);
            yield return WaitFor(() => RemoteConfigClient.Get("from", "") == "agent", "the live config", 15f);
            yield return WaitFor(() => _agent.Heartbeats.Count > 0, "heartbeats to resume");
        }

        [UnityTest]
        public IEnumerator AWrongTokenNeverTakesTheAppDown()
        {
            _agent.SetConfig(1, new { v = 1 });
            StartClient(o => o.Token = "wrong");
            yield return new WaitForSecondsRealtime(1.5f);
            Assert.IsNotNull(_client.Session, "the client carries on");
            Assert.IsFalse(_client.IsConnected, "rejected is not connected");
            Assert.AreEqual(0, _agent.Heartbeats.Count, "the agent rejected every request");
            Assert.AreEqual(0, _client.ConfigRevision);
            // and the app is still free to use the defaults it passes to Get
            Assert.AreEqual(5, RemoteConfigClient.Get("anything", 5));
        }

        // ---------------------------------------------------------------- quit hook

        [UnityTest]
        public IEnumerator AQuitRequestIsRaisedOnceAndDoesNotQuitWhenDisabled()
        {
            StartClient(); // QuitWhenAsked = false
            var requests = new List<QuitRequest>();
            _client.QuitRequested += requests.Add;
            yield return WaitFor(() => _client.Session.AgentReachable, "the agent");

            _agent.RequestQuit("restart requested: command cmd_1", 8);
            yield return WaitFor(() => requests.Count == 1, "the quit request");
            Assert.AreEqual("restart requested: command cmd_1", requests[0].Reason);
            Assert.AreEqual(8, requests[0].GraceSeconds);

            // the request stays pending until the process exits; the app must not be told again
            yield return new WaitForSecondsRealtime(3f);
            Assert.AreEqual(1, requests.Count);
            Assert.IsNotNull(_client.Session.LastQuitRequest);

            // a new request after the old one was withdrawn is a new event
            _agent.ClearQuit();
            yield return new WaitForSecondsRealtime(2.6f);
            _agent.RequestQuit("second", 3);
            yield return WaitFor(() => requests.Count == 2, "the second quit request", 8f);
            Assert.AreEqual("second", requests[1].Reason);
        }

        [UnityTest]
        public IEnumerator AHandlerThatThrowsOnQuitDoesNotBreakTheClient()
        {
            StartClient();
            var second = 0;
            _client.QuitRequested += _ => throw new Exception("save failed");
            _client.QuitRequested += _ => second++;
            LogAssert.Expect(LogType.Exception, new System.Text.RegularExpressions.Regex("save failed"));
            _agent.RequestQuit("x", 5);
            yield return WaitFor(() => second == 1, "the other quit handler");
            yield return WaitFor(() => _agent.Heartbeats.Count > 2, "heartbeats to carry on");
        }

        // ---------------------------------------------------------------- metrics and events

        [UnityTest]
        public IEnumerator MetricsAndEventsAreBatchedAndSent()
        {
            StartClient();
            _client.ReportMetric("visitors", 42, new Dictionary<string, string> { ["zone"] = "lobby" });
            _client.ReportMetric("visitors", 43);
            _client.ReportEvent("scene.loaded", "Lobby", EventLevel.Info, new Dictionary<string, object> { ["ms"] = 812 });

            yield return WaitFor(() => _agent.Events.Count == 1, "the event batch", 8f);
            var e = _agent.Events[0];
            Assert.AreEqual("scene.loaded", (string)e["type"]);
            Assert.AreEqual("info", (string)e["level"]);
            Assert.AreEqual(812, (int)e["data"]["ms"]);
            Assert.IsNotNull(e["ts"]);

            yield return WaitFor(() => _agent.Metrics.Count == 2, "the metric batch", 8f);
            Assert.AreEqual("visitors", (string)_agent.Metrics[0]["name"]);
            Assert.AreEqual(42, (double)_agent.Metrics[0]["value"], 1e-9);
            Assert.AreEqual("lobby", (string)_agent.Metrics[0]["tags"]["zone"]);
        }

        [UnityTest]
        public IEnumerator AnErrorEventIsSentPromptlyRatherThanWaitingForTheBatchTimer()
        {
            StartClient();
            yield return WaitFor(() => _client.Session.AgentReachable, "the agent");
            var t0 = Time.realtimeSinceStartup;
            _client.ReportEvent("app.crash_imminent", "disk full", EventLevel.Error);
            yield return WaitFor(() => _agent.Events.Count == 1, "the error event", 6f);
            Assert.Less(Time.realtimeSinceStartup - t0, 4f, "an error should not sit in a 10 s batch");
        }

        [UnityTest]
        public IEnumerator UnityErrorsAreForwardedWithinThePerMinuteLimit()
        {
            StartClient(o => { o.ForwardErrors = true; o.MaxForwardedErrorsPerMinute = 3; });
            yield return WaitFor(() => _client.Session.AgentReachable, "the agent");

            for (var i = 0; i < 5; i++)
            {
                LogAssert.Expect(LogType.Error, "boom " + i);
                Debug.LogError("boom " + i);
            }
            yield return WaitFor(() => _agent.Events.Count >= 3, "forwarded errors", 8f);
            yield return new WaitForSecondsRealtime(1.5f);

            var forwarded = _agent.Events.Where(e => (string)e["type"] == "app.error").ToList();
            Assert.AreEqual(3, forwarded.Count, "the rest were over the limit");
            Assert.AreEqual("error", (string)forwarded[0]["level"]);
            StringAssert.Contains("boom 0", (string)forwarded[0]["message"]);
        }

        [UnityTest]
        public IEnumerator ErrorsAreNotForwardedWhenSwitchedOff()
        {
            StartClient(); // ForwardErrors = false
            yield return WaitFor(() => _client.Session.AgentReachable, "the agent");
            LogAssert.Expect(LogType.Error, "quiet");
            Debug.LogError("quiet");
            yield return new WaitForSecondsRealtime(1.5f);
            Assert.IsFalse(_agent.Events.Any(e => (string)e["type"] == "app.error"));
        }

        [UnityTest]
        public IEnumerator OnlyOneClientCanExist()
        {
            StartClient();
            Assert.Throws<InvalidOperationException>(() => RemoteConfigClient.Create(Options(), false));
            yield return null;
        }
    }
}
