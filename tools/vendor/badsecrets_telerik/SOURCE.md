# Badsecrets Telerik Resources

This directory vendors the minimal offline Telerik `ConfigurationHashKey` matcher
and its two upstream key resources from Badsecrets 1.2.1:

- `modules/passive/telerik_hashkey.py`
- `resources/aspnet_machinekeys.txt`
- `resources/telerik_hash_keys.txt`

The local Telerik matcher retains only the passive HMAC-SHA256 check. The separate
`tools/aspnet_viewstate_knownkey.py` wrapper uses the pinned Badsecrets 1.2.1
`ASPNET_Viewstate` implementation with this directory's machineKey resource. No
upstream active HTTP tooling is called.
