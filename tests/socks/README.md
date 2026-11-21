# SOCKS integration tests

The tests start local HTTP, TCP and SOCKS servers, generate nginx
configuration, run requests through the xproxy modules and write a JSON report.
Only Python 3, OpenSSL and an nginx build with the modules are required.

## Build

Normal build:

```bash
cd nginx-1.30.7
patch -p1 < /path/to/nginx_xproxy_module/http/patch_1.24.0.patch
./configure --with-debug --with-http_ssl_module \
    --with-stream --with-stream_ssl_module --with-compat \
    --add-dynamic-module=/path/to/nginx_xproxy_module/http \
    --add-dynamic-module=/path/to/nginx_xproxy_module/stream
make -j4
```

ASan/UBSan build:

```bash
./configure --with-debug --with-http_ssl_module \
    --with-stream --with-stream_ssl_module --with-compat \
    --add-dynamic-module=/path/to/nginx_xproxy_module/http \
    --add-dynamic-module=/path/to/nginx_xproxy_module/stream \
    --with-cc-opt='-O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer' \
    --with-ld-opt='-fsanitize=address,undefined'
make -j4
```

## Run

```bash
python3 tests/socks/run.py \
    --nginx /path/to/nginx \
    --http-module /path/to/ngx_http_xproxy_module.so \
    --stream-module /path/to/ngx_stream_xproxy_module.so \
    --label normal-1.30 \
    --mode all
```

Modes:

- `functional` — SOCKS4/4a/5/5h, auth, resolve modes, HTTP and stream data.
- `fuzz` — malformed and truncated SOCKS replies.
- `stress` — concurrent HTTP and stream traffic.
- `leak` — ASan/LSan run with `master_process off` (requires an ASan build).
- `all` — functional, fuzz and stress, with a soak run.

Options:

- `--workdir DIR` — report and log directory, default
  `/tmp/opencode/xproxy-socks-tests`.
- `--soak SECONDS` — soak duration for `all`, default 1800.
- `--asan` — set sanitizer options and check sanitizer logs.
- `--keep` — keep temporary nginx directories.

Every run creates `report-<label>.json` in `<workdir>/<label>/`. The report
contains passed, failed and known-limitation cases. The process exits non-zero
only for unexpected failures.

## Known limitation

`xproxy_socks_resolve local` requires an IP literal as the target. A domain
target in local mode is reported as a known limitation; use the default
`xproxy_socks_resolve proxy` for remote DNS.
