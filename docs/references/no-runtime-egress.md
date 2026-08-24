## Description

Source code and manifests in RHOAI component repos must not contain hardcoded external URLs that would cause runtime failures in disconnected/air-gapped environments. In a disconnected cluster, there is no outbound internet access — any HTTP call to an external service will hang and eventually time out, causing pod crashes, degraded functionality, or silent data-path failures that are difficult to diagnose.

This rule is evaluated by the [disconnected-readiness-scorer](https://github.com/opendatahub-io/disconnected-readiness-scorer) static analysis tool. It detects outbound HTTP calls, external URL references, and model download patterns across multiple languages.

## What the Check Verifies

The rule scans source code (`.go`, `.py`, `.ts`, `.tsx`, `.sh`) and YAML manifests for network call patterns:

### Go
- `http.Get`, `http.Post`, `http.Head`, `http.Do`, `http.NewRequest`
- `net.Dial`, `http.DefaultClient`
- `exec.Command("git")` subprocess calls

### Python
- `requests.get/post/put/delete`, `urllib.request.urlopen`, `httpx.*`, `aiohttp.ClientSession`
- HuggingFace model downloads: `from_pretrained()`, `snapshot_download()`, `load_dataset()`, `SentenceTransformer()`, `torch.hub.load()`
- `subprocess` calls with `curl`, `wget`, or `huggingface-cli download`

### TypeScript/TSX
- `fetch()`, `axios.get/post/put/delete`, `http.request`

### Shell / YAML
- `curl`, `wget` invocations
- `hf download`, `huggingface-cli download`

YAML scanning also detects `curl`/`wget` calls embedded in Kubernetes CronJob, Job, and Pod `command:` or `args:` fields. Only git-tracked files are scanned.

### Severity classification

| Condition | Severity |
|-----------|----------|
| HuggingFace model download patterns | Always blocker |
| Hardcoded external URL (http:// or https://) | blocker |
| Configurable URL (line contains `os.Getenv`, `os.environ`, `config.`, `settings.`, `process.env`, `viper.`, `${`, `getenv`) | info |
| Cluster-internal URL (`kubernetes.default.svc`, `*.svc.cluster.local`, `localhost`, `127.0.0.1`, `0.0.0.0`, or hostnames without dots) | info |
| No hardcoded URL present (likely internal/relative API call) | info |

## Common Failures

| Failure | Language | Severity | Example |
|---------|----------|----------|---------|
| HuggingFace model download | Python | blocker | `model = AutoModel.from_pretrained("bert-base-uncased")` |
| Hardcoded external URL | Go | blocker | `resp, _ := http.Get("https://api.github.com/repos/...")` |
| curl in CronJob manifest | YAML | blocker | `command: ["curl", "https://external.api.com/health"]` |
| wget in shell script | Shell | blocker | `wget https://downloads.example.com/model.bin` |
| Configurable API endpoint | Python | info | `url = os.environ.get("API_URL", "https://default.api.com")` |

## Guidance

### Option 1: Make the URL configurable

Replace hardcoded URLs with environment variables that operators can override for internal mirrors:

**In your Python code:**
```python
# Before (blocker)
response = requests.get("https://huggingface.co/models/bert")

# After (configurable — info severity)
model_url = os.environ.get("MODEL_REGISTRY_URL", "https://huggingface.co")
response = requests.get(f"{model_url}/models/bert")
```

**In your operator overlay** (so the mirror URL is injected in disconnected deployments):
```yaml
env:
  - name: MODEL_REGISTRY_URL
    value: "https://mirror.internal.example.com/huggingface"
```

### Option 2: Pre-cache model artifacts

For ML model downloads, pre-cache the model artifacts into the container image at build time instead of downloading at runtime:

```dockerfile
RUN python -c "from transformers import AutoModel; AutoModel.from_pretrained('bert-base-uncased', cache_dir='/models')"
```

Then load from the local cache at runtime:

```python
model = AutoModel.from_pretrained("/models/bert-base-uncased")
```

### Option 3: Remove the external dependency

If the external call is for optional functionality (telemetry, update checks, non-critical health probes), make it conditional or remove it entirely for disconnected deployments.

### False positives

HTTP client setup code that constructs a client but only calls internal endpoints, URLs that are configurable but where the config read happens on a different line, and files outside production scope are common false positives. The scanner detects configurability by looking for `os.Getenv`, `config.`, `viper.`, `${...}` on the same line — if the config read is on a different line, it may miss it. Verify manually and add a path exclusion if confirmed safe.

## References

- [Remediation guide](https://github.com/opendatahub-io/disconnected-readiness-scorer/blob/main/docs/remediation-guide.md#3-runtime-network-egress-no-runtime-egress) — investigation workflow and false positive identification
- [Rules reference](https://github.com/opendatahub-io/disconnected-readiness-scorer/blob/main/docs/rules-reference.md#rule-no-runtime-egress) — implementation details
- [Rule source](https://github.com/opendatahub-io/disconnected-readiness-scorer/blob/main/rules/no_runtime_egress.py)
