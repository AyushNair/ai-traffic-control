# AI Traffic Control

AI Traffic Control is a local-first Windows desktop app and HTTP gateway for AI clients that support a custom OpenAI-compatible base URL. It inspects only requests deliberately sent to its local endpoint. It does not discover, monitor, or intercept unrelated Windows applications, and it does not install certificates.

The app opens in **Demo preview** with clearly labeled, in-memory sample records for presentations. These samples are not live traffic and are never written to the local audit database. Switch the top-right control to **Live data** to view actual gateway records.

## Quick start (Windows)

### Standalone desktop build

Build the standalone app by running `Build Windows App.ps1`, then open `dist-demo\AI Traffic Control\AI Traffic Control.exe` or use `Open Built App.bat`. The packaged app does not require a separate Python installation. Keep the whole `AI Traffic Control` folder together when moving it to another PC.

To rebuild the Windows package from source, run `Build Windows App.ps1`. It installs any missing packaging dependencies and creates a standalone folder under `dist-demo\`.

### Run from source

1. Install Python 3.10 or newer and ensure `python` (or the Python launcher `py -3`) is available on PATH.
2. Double-click `Launch AI Traffic Control.bat`. The launcher creates `.venv` when needed, installs the dependencies, and starts the desktop application.
3. In **Settings**, enter an OpenAI-compatible provider URL, model, and API key. The key is saved through the Windows credential store using `keyring`; it is not saved in SQLite or app settings. The app makes no provider call until you explicitly choose **Check provider connection** or a client sends an allowed request.
4. On launch, the app starts its gateway on `127.0.0.1`. The default endpoint is `http://127.0.0.1:8765/v1`; the Overview screen shows whether the listener actually started. No upstream call is made at startup.
5. In a compatible client, set its API base URL to that endpoint and its API key to any placeholder value if the client requires one. Configure the real provider credential only in this app. Apps without a custom endpoint or supported integration are not inspected.

For an OpenAI Python client, point `base_url` at the local endpoint and use a placeholder key for the client-side requirement. The gateway ignores that incoming authorization value and uses the credential stored in its Windows keyring:

```python
from openai import OpenAI

client = OpenAI(
    base_url="http://127.0.0.1:8765/v1",
    api_key="local-client-placeholder",
)
response = client.chat.completions.create(
    model="client-model",  # The model configured in AI Traffic Control is used upstream.
    messages=[{"role": "user", "content": "Hello"}],
    stream=False,
)
```

Use `stream=False`; streaming requests return HTTP 501. Clients that cannot set a custom base URL or supported integration will bypass this gateway and will not be inspected.

## Product behavior

- Requests are evaluated locally before any upstream request. Policy outcomes are Allow, Review, or Deny. A review is held in memory and is forwarded only after an explicit approval. A denial, timeout, shutdown, invalid request, or policy failure does not forward it.
- The gateway supports the OpenAI chat-completions JSON request format and `/v1/models`. Streaming requests receive HTTP 501 with a clear explanation; set `stream` to `false` in the AI client.
- Email, phone, payment-card (Luhn), common token, private-key, and user-defined keyword/regular-expression detectors provide findings and a readable trace. Matched values are masked in the interface by default.
- SQLite stores local metadata and cases, never original prompts, credentials, authorization headers, or detected raw secret values. At most 100 recent bodies (up to 1 MiB each and 10 MiB total) are held only in process memory for inspection; pending reviews have a 16 MiB combined memory limit. These bodies are cleared when the gateway stops. Oversized review queues fail closed.
- Local audit metadata can be filtered and exported as CSV. Demo examples are separately labeled and never represented as live traffic.
- Demo preview data is isolated in memory and labeled in the interface; the **Live data** view reports only requests recorded by the local gateway.

## Local data and privacy

Application settings and the SQLite database live under the current user's local application data directory. The gateway binds to `127.0.0.1` by default. Settings offer only loopback addresses (`127.0.0.1` or `localhost`), so the app does not expose the gateway to other devices on the network. If the configured port is unavailable, the gateway searches the next 31 local ports and saves the first available one. The Overview screen displays the actual endpoint; update AI clients to use that URL. This software is a local inspection tool, not a compliance certification or a claim of enterprise security.

## Provider compatibility

The configured provider must expose an OpenAI-compatible API. Enter its base URL (for example, an endpoint ending in `/v1`) and model name. The gateway forwards only the compatible paths it implements. Provider credentials remain in Windows Credential Manager through the system keyring backend. A provider account and user-supplied API key are required for real upstream completions.

## Development

See `requirements.txt` and `pyproject.toml` for dependencies. Start the program with `python -m traffic_control` from this directory after installing the dependencies.

Run the offline regression suite from this directory with:

```powershell
python -m unittest discover -s tests -v
```

The suite covers policy outcomes, secret masking, invalid rule rejection, audit payload exclusion, loopback port selection, and fallback-port persistence. It uses no provider credentials or upstream network calls. A release build should also be smoke-tested on a clean Windows account with a fresh user data directory before distribution.

