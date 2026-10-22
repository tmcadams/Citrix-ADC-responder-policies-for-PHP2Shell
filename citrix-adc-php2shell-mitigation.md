# Citrix ADC / NetScaler mitigations for PHP2Shell

Community notes on temporary edge controls for PHP applications behind Citrix ADC / NetScaler (VPX, MPX, SDX) while you patch PHP. Use these alongside the php.ini changes below, not instead of patching.

**Fixed PHP versions:** 8.5.12, 8.4.27, 8.3.36, 8.2.35. End-of-life branches (5.x, 7.x) get no fix, so on those hosts edge controls and php.ini changes are your only options.

> **Disclaimer:** Provided as-is, with no warranty. These use advanced policy syntax (13.x / 14.x). Test every expression on a non-production vserver, check the bind order against your existing policies, and roll out in log-only mode first.

## What the policies target

| Policy | Matches | Suggested action | Why |
| --- | --- | --- | --- |
| `rsp_php_uplprog` | `PHP_SESSION_UPLOAD_PROGRESS` in the query string or first 8 KB of the body | Block (403) | The upload-progress feature is part of the attack path |
| `rsp_php_postmax` | POST with Content-Length above your hard ceiling (example: 32 MB) | Block (413) | Oversized request bodies |
| `rsp_php_postwarn` | POST with Content-Length above `post_max_size` (example: 8 MB) | Log, then block | Promote to blocking once you know your apps' real upload sizes |
| `rsp_php_chunked` | POST with `Transfer-Encoding: chunked` | Log, then decide | Chunked bodies carry no Content-Length, so size rules miss them |

Set the size thresholds for your own environment. Many apps legitimately accept large uploads, and some clients send chunked POSTs.

## Option 1: Responder policies (all license editions)

### Actions

```
add responder action rsa_php_403 respondwith q{"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"}
add responder action rsa_php_413 respondwith q{"HTTP/1.1 413 Payload Too Large\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"}

add audit messageaction ama_php2shell INFORMATIONAL q{"php2shell " + CLIENT.IP.SRC + " " + HTTP.REQ.HOSTNAME + " " + HTTP.REQ.URL.PATH.HTTP_URL_SAFE + " cl=" + HTTP.REQ.CONTENT_LENGTH}
set audit syslogParams -userDefinedAuditlog YES
```

If you use a custom syslog action, set `-userDefinedAuditlog YES` on that action too.

### Policies

Adjust the byte values to suit your environment (33554432 = 32 MB, 8388608 = 8 MB).

```
add responder policy rsp_php_uplprog q{HTTP.REQ.URL.QUERY.SET_TEXT_MODE(IGNORECASE).CONTAINS("PHP_SESSION_UPLOAD_PROGRESS") || (HTTP.REQ.METHOD.EQ(POST) && HTTP.REQ.BODY(8192).SET_TEXT_MODE(IGNORECASE).CONTAINS("PHP_SESSION_UPLOAD_PROGRESS"))} rsa_php_403 -logAction ama_php2shell

add responder policy rsp_php_postmax q{HTTP.REQ.METHOD.EQ(POST) && HTTP.REQ.CONTENT_LENGTH.GT(33554432)} rsa_php_413 -logAction ama_php2shell

add responder policy rsp_php_postwarn q{HTTP.REQ.METHOD.EQ(POST) && HTTP.REQ.CONTENT_LENGTH.GT(8388608)} NOOP -logAction ama_php2shell

add responder policy rsp_php_chunked q{HTTP.REQ.METHOD.EQ(POST) && HTTP.REQ.HEADER("Transfer-Encoding").SET_TEXT_MODE(IGNORECASE).CONTAINS("chunked")} NOOP -logAction ama_php2shell
```

If you changed `session.upload_progress.name` from its default, match your custom name instead.

### Binding per vserver (recommended)

Bind the log-only rules first with `NEXT` and the blocking rules after them with `END`. Pick priorities that don't collide with your existing responder bindings.

```
bind lb vserver <VSERVER> -policyName rsp_php_postwarn -priority 100 -gotoPriorityExpression NEXT -type REQUEST
bind lb vserver <VSERVER> -policyName rsp_php_chunked  -priority 110 -gotoPriorityExpression NEXT -type REQUEST
bind lb vserver <VSERVER> -policyName rsp_php_uplprog  -priority 120 -gotoPriorityExpression END  -type REQUEST
bind lb vserver <VSERVER> -policyName rsp_php_postmax  -priority 130 -gotoPriorityExpression END  -type REQUEST
```

For content switching vservers, use `bind cs vserver` with the same arguments.

### Binding globally (alternative)

This rolls out faster, but it applies to every vserver, including ones that don't serve PHP.

```
bind responder global rsp_php_postwarn 100 NEXT -type REQ_DEFAULT
bind responder global rsp_php_chunked  110 NEXT -type REQ_DEFAULT
bind responder global rsp_php_uplprog  120 END  -type REQ_DEFAULT
bind responder global rsp_php_postmax  130 END  -type REQ_DEFAULT
```

### Promoting log-only rules to blocking

Once the logs show no legitimate hits:

```
set responder policy rsp_php_postwarn -action rsa_php_413
set responder policy rsp_php_chunked  -action rsa_php_403
```

## Option 2: Web App Firewall (Premium license)

If you have AppFW, a profile can enforce request size limits and field-format checks per URL, and its learning mode helps you find legitimate large uploads. Watch for signature updates that cover this issue. AppFW is more precise than responder rules but slower to tune, so responder policies are the quicker stopgap.

## Option 3: Upstream WAF

If a cloud WAF also proxies your sites, enable that vendor's managed rules for this issue. Hostnames that are DNS-only (not proxied) get no protection from the WAF, so keep the ADC policies in place.

## Verify

```
show responder policy rsp_php_uplprog
stat responder policy
show lb vserver <VSERVER>
```

- Check that normal page loads and normal uploads still work through each vserver.
- Send a test POST with `PHP_SESSION_UPLOAD_PROGRESS` in the body. You should get a 403.
- Confirm the audit messages reach your syslog server (search for `php2shell`).

## Save and sync

```
save ns config
```

On an HA pair, make the changes on the primary and confirm that `show ha node` reports a successful sync.

## Rollback

```
unbind lb vserver <VSERVER> -policyName rsp_php_uplprog  -type REQUEST
unbind lb vserver <VSERVER> -policyName rsp_php_postmax  -type REQUEST
unbind lb vserver <VSERVER> -policyName rsp_php_postwarn -type REQUEST
unbind lb vserver <VSERVER> -policyName rsp_php_chunked  -type REQUEST
save ns config
```

## Pair with php.ini changes

Edge rules can be bypassed (TLS passthrough, direct-to-origin access, internal paths). On every PHP host, also set the following and then restart all PHP workers (php-fpm, Apache, IIS FastCGI):

```
session.upload_progress.enabled = 0
post_max_size = 8M        ; raise where your apps need larger uploads
upload_max_filesize = 7M  ; keep below post_max_size
memory_limit = -1
```

On PHP 8.5, also set `fatal_error_backtraces = 0`. Don't use RLIMIT_AS or RLIMIT_DATA as a workaround. Patch to a fixed version as soon as you can.

## Contributing

Corrections and tested variations are welcome. Please note your ADC firmware version when you report results.

## License

MIT
