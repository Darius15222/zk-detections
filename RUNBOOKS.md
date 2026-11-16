# Runbooks

One section per alerting rule in `rules/sigma/`. Each answers: what it means, what to check, what to do, when it is a false positive. Queries are for Kibana Discover (KQL). Data streams: `logs-zkauth-default`, `logs-suricata-default`.

In the lab every request reaches zk-auth through Traefik, and inside k3d `source.ip` is often the node address (`10.42.0.1`). Treat `source.ip` as weak evidence there and lean on `user.name` and timing.

## zk-auth brute force from one source

**Means:** ten or more failed logins from one `source.ip` in five minutes (T1110.001, password guessing).

**Check**
1. Which users were targeted: `event.outcome: failure and source.ip: "<ip>"`, split by `user.name`. One user is guessing; many users is credential stuffing or spraying.
2. Did it work: `event.outcome: success and source.ip: "<ip>"` after the first failure. A success after a run of failures is a compromised account until proven otherwise.
3. Did the lockout engage: `event.reason: rate_limited` for the same pair. If it did, the guessing stopped at ten attempts per user.

**Do**
- No success: nothing to contain, the lockout already throttles the pair. Record the source.
- A success followed the failures: treat the account as compromised. Password user: reset the password. ZK user: register a new public key.
- The source keeps coming back after each window: block it at the ingress.

**False positive:** several users behind one NAT mistyping passwords; in the lab, any test run, because all traffic shares one source address.

## zk-auth Schnorr proof replay

**Means:** a zero-knowledge login reused a nonce that was already consumed (T1550). Someone captured a proof in transit and sent it again. The replay itself always fails: a nonce is single use.

**Check**
1. The original login: `event.action: login-zk and user.name: "<user>"` just before the alert. A success from one `source.ip` followed by `nonce_reuse` from another means the proof was captured on the path between the two.
2. Same `source.ip` for both, within a second or two: more likely a client retry than an attacker.

**Do**
- Different source: the secret key is not exposed (the proof reveals nothing about it), but something on the path can read traffic. Check TLS termination and who can see traffic between Traefik and the pod.
- Same source: no action; note the client bug if it repeats.

**False positive:** a client that retries the same request after a timeout.

## zk-auth forged Schnorr proof

**Means:** a zero-knowledge login with a fresh, valid nonce failed verification (T1110). The prover does not hold the secret key for the registered public key.

**Check**
1. How many and how fast: `event.reason: invalid_proof and user.name: "<user>"`. One or two is a wrong key; a steady stream is someone trying keys, which cannot succeed by guessing.
2. Whether the same source also triggers the brute force or replay rules: together they describe one actor probing the service.

**Do**
- Isolated: contact the user; they probably rotated or lost their key and need to register a new one.
- Stream from one source: the lockout limits it to ten per window. Block the source at the ingress if it persists.

**False positive:** a user whose client lost or rotated its key.

## Suricata ZK-LAB login burst

**Means:** Suricata rule 9000001 saw 20 or more POSTs to `/login/` from one source in 60 seconds (T1110). This is the network-side view of a brute force, independent of the application logs.

**Check**
1. Is there a matching application alert (brute force from one source) in the same minutes? Both firing is the expected picture.
2. Only this one fired: either the logins were succeeding (load, not attack) or zk-auth logs are not arriving. Check that `logs-zkauth-default` has events for the same window.

**Do**
- With the application alert: follow the brute force runbook above.
- Without it and zk-auth logs are missing: treat it as a telemetry gap first (Elastic Agent, Logstash), then as an attack.

**False positive:** load tests against the auth service.
