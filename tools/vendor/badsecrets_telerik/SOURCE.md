# Badsecrets Telerik Resources

This directory vendors the minimal offline Telerik `ConfigurationHashKey` matcher
and its two upstream key resources from Badsecrets 1.2.1:

- `modules/passive/telerik_hashkey.py`
- `resources/aspnet_machinekeys.txt`
- `resources/telerik_hash_keys.txt`

Only the passive HMAC-SHA256 check is retained. The upstream active HTTP tooling,
YARA dependency, and unrelated modules are deliberately excluded.
