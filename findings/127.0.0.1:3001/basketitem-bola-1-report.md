# BOLA: cross-actor basket-item read on /api/BasketItems/<id> (witness /api/BasketItems/1)

## Summary

GET http://127.0.0.1:3001/api/BasketItems/1 with a peer account returns the basket item (ProductId=1, BasketId=1, quantity=2) byte-identically to any other authenticated account's request (200, 154B). Only the Authorization header differs. BasketId=1 belongs to another user (UserId=2), so this is an object-ownership bypass on the Sequelize /api surface.

## Sibling-family answer (AQ-0022)

The missing ownership check extends beyond /rest/basket/<id> into /api/BasketItems/<id>. Complementary probes on the same surface: Feedbacks/1 (200, public feedback data), Deliverys/1 (200, catalog data, no ownership), Recycles/1 (200, list containing other users' UserId records), Complaints/1 and SecurityQuestions/1 (401 — auth required), Quantitys/1 (403 — admin gate).

## Impact

Any authenticated user can read other users' basket items (product, quantity, basket binding) by sequential id enumeration. CVSS 4.3 (AV:N/AC:L/PR:L/UI:N/VC:L).

## Evidence

- Runner: evidence/127.0.0.1:3001/validation/basketitem-bola-1/20260912T152622238934Z-522c3c6c/summary.json
- Basket matrix (root-cause family): findings/127.0.0.1:3001/AQ-0002-report.md
