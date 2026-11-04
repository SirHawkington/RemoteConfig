using System.Collections.Generic;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using UnityEngine.Networking;

namespace RemoteConfig
{
    /// <summary>Sends requests with UnityWebRequest. Must be called on the main thread, which the session's loops are.</summary>
    public sealed class UnityWebRequestTransport : IRemoteTransport
    {
        readonly string _baseUrl;
        readonly string _token;

        public UnityWebRequestTransport(string baseUrl, string token)
        {
            _baseUrl = (baseUrl ?? "").TrimEnd('/');
            _token = token ?? "";
        }

        public Task<TransportResponse> SendAsync(string method, string path, string jsonBody,
            IDictionary<string, string> headers, int timeoutSeconds, CancellationToken ct)
        {
            var tcs = new TaskCompletionSource<TransportResponse>();
            var req = new UnityWebRequest(_baseUrl + path, method) { downloadHandler = new DownloadHandlerBuffer() };
            req.timeout = timeoutSeconds;
            if (jsonBody != null)
            {
                req.uploadHandler = new UploadHandlerRaw(Encoding.UTF8.GetBytes(jsonBody)) { contentType = "application/json" };
            }
            if (_token.Length > 0) req.SetRequestHeader("Authorization", "Bearer " + _token);
            if (headers != null)
            {
                foreach (var kv in headers) req.SetRequestHeader(kv.Key, kv.Value);
            }

            CancellationTokenRegistration registration = default;
            var op = req.SendWebRequest();
            if (ct.CanBeCanceled) registration = ct.Register(() => { if (!req.isDone) req.Abort(); });

            op.completed += _ =>
            {
                registration.Dispose();
                var response = new TransportResponse { Status = (int)req.responseCode };
                // Connection and data errors have no usable status; HTTP errors (4xx/5xx) do, and the caller reads it.
                if (req.result == UnityWebRequest.Result.ConnectionError || req.result == UnityWebRequest.Result.DataProcessingError)
                {
                    response = TransportResponse.Failure(req.error);
                }
                else
                {
                    response.Body = req.downloadHandler != null ? req.downloadHandler.text : "";
                }
                req.Dispose();
                tcs.TrySetResult(response);
            };
            return tcs.Task;
        }
    }
}
