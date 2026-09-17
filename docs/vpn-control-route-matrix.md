# VPN control route matrix

Status: Phase 1 complete; independent engineering review accepted 2026-09-16.
Phase 2 routes use the application seam while preserving exactly 48 current
method/path pairs are mapped below. Internal paths omit the reverse proxy's
single `/api` prefix. Existing response schemas/statuses remain the public
contract; the [protocol](vpn-control-protocol.md) describes internal operations.

Every management permission is the exact dependency in authorization.py.
Delegated sysadmin and app-only ServiceAdmin have all management permissions;
device_user has no management permissions. Self-service uses verified principal
plus explicit local ownership/grants, never role-based shortcuts. Shared-profile
download accepts each authenticated current role, including app-only admin.
A Device AccessGrant is API business visibility, not a VPN firewall rule;
UserClient ownership is separate from both. The /networks routes intentionally
use server permissions, and administrative credential download intentionally
requires clients:write. Do not infer permissions from HTTP method names.

The two connection endpoints retain clients:write for authenticated callers.
Their existing precise local-hook exception remains only in unchanged host
behavior during transition. Agent daemon events use trusted UDS polling;
there is no JSON impersonation, unauthenticated agent callback or loopback
bypass in the target. Existing ownership/not-found/precondition behavior stays.

All mutating agent workflows use pending API intent, durable per-step operation
IDs, generation compare-and-set and recorded completion before public success.
Multiple calls in one row are distinct durable steps; no cross-process atomic
transaction is implied. Unknown outcome always queries the original ID before
compensation. Reversible compensation is a new recorded intent with current
generation and ownership checks. Never reverse committed revocation, remove
CA history, or touch administrator-owned routes/rules/unrelated CCD pushes.
Read rows have no desired-state mutation unless explicitly stated.

Audit column names are planned application audit event types, not new runtime
logging. Each event records opaque request/operation IDs, opaque local actor/
resource IDs, outcome code, generation and effect/compensation status; no raw
issuer/subject/token/name/address/path/PEM/ZIP/SAS URL. Record denied/failed
attempts with the same safe action type and fixed outcome. For downloads record
started/completed/cancelled without bytes or credentials. Local grants/ownership
changes are auditable without implying any agent call. All API DB-only changes
use their existing transaction boundaries.

| Method | Path | Permission / ownership | Domain owner | Desired-state change | Agent calls | Compensation / recovery | Audit event |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `POST` | `/server` | server:write | API Server/profile; agent actual config | Create server/address pool and profile generation | ServerConfig | Restore prior profile and roll back DB initialization | `server.initialize` |
| `GET` | `/server` | server:read | API Server read model | None | None (ServerConfig during reconciliation) | None | `server.read` |
| `PUT` | `/server/client-config` | server:write | API shared profile | Replace profile using explicit remote endpoint | ServerConfig | Restore prior atomic profile if DB generation commit fails | `profile.replace` |
| `GET` | `/server/health` | server:read | Agent actual health; API projection | None | Health | None | `server.health` |
| `GET` | `/server/assignable-virtual-addresses` | server:read | API address-pool ownership | None | None | None | `address.list` |
| `GET` | `/server/routes` | server:read | Agent owned route snapshot; API projection | None | ListRoutes | None | `route.list` |
| `POST` | `/server/routes` | server:write | API route intent; agent owned routes | Persist route present | SetRoute(present=true) | Restore prior owned intent after proven outcome; reconcile uncertain ID | `route.ensure` |
| `DELETE` | `/server/routes` | server:write | API route intent; agent owned routes | Persist route absent | SetRoute(present=false) | Restore only prior owned route if desired transaction fails | `route.remove` |
| `POST` | `/clients` | clients:write | API Client/Cert; agent PKI | Persist pending new client/operation | ChangeClient(issue), GetClient | Reconcile issued identity; never issue twice after DB failure | `client.create` |
| `GET` | `/clients` | clients:read | API Client records | None | None | None | `client.list` |
| `GET` | `/clients/{client_name}` | clients:read | API Client/Cert/address/history | None | None (GetClient during reconciliation) | None | `client.read` |
| `PUT` | `/clients/{client_name}/package-cert` | clients:write | API archives; agent active credential generation | Record package/cache generation | GetClient, Archive | Remove incomplete staged archive; retain previous valid generation | `certificate.package` |
| `GET` | `/clients/{client_name}/download-cert` | clients:write | API authorized archive delivery | No business change; validate archive generation | GetClient; Archive on cache miss | Close/cancel stream, discard partial staging | `certificate.download` |
| `PUT` | `/clients/{client_name}/renew-cert` | clients:write | API Cert/archive records; agent PKI/CRL | Persist renewal and invalidate old archive generation | ChangeClient(renew), GetClient | Reconcile committed renewal/CRL; never restore invalidated credential | `certificate.renew` |
| `PUT` | `/clients/{client_name}/revoke` | clients:write | API revoked state; agent PKI/CRL/sessions | Persist revocation and archive invalidation | ChangeClient(revoke), ListSessions; Disconnect if reconciliation requires | Never undo committed revocation; reconcile DB and archive cleanup | `client.revoke` |
| `DELETE` | `/clients/{client_name}` | clients:write | API relationships/history/archives; agent revoked leaf/CCD | Require revoked client; persist deletion workflow | ChangeClient(delete) | Restore staged reversible leaf cleanup only before commit; never CA history; retry Blob orphan cleanup | `client.delete` |
| `PUT` | `/clients/{client_name}/assign-ip` | clients:write | API exclusive pool ownership; agent owned CCD | Persist assignment for active client plus canonical CIDR | SetAssignment(address, optional network) | Restore previous owned assignment after proven outcome; preserve unrelated CCD | `address.assign` |
| `DELETE` | `/clients/{client_name}/unassign-ip` | clients:write | API pool ownership; agent owned CCD | Release assigned address | SetAssignment(null) | Restore previous owned assignment if desired DB commit fails | `address.unassign` |
| `POST` | `/clients/{client_name}/connections` | clients:write; legacy host hook exception | API Connection history | Persist authorized manual connect history | None; agent daemon ingestion uses PollEvents/AckEvents separately | DB rollback; event ingestion deduplicates before acknowledgment | `connection.start` |
| `PUT` | `/clients/{client_name}/connections` | clients:write; legacy host hook exception | API Connection history | Close matching active history record | None; agent daemon ingestion uses PollEvents/AckEvents separately | DB rollback; missing active connection remains 404 | `connection.end` |
| `POST` | `/clients/import` | clients:write | API import/upsert; agent existing metadata | Transactional client/cert/address and optional device upsert; preserve skip/conflict counts | ListClients; GetClient when needed | Roll back failed DB item/transaction; no issuance or source PKI changes | `client.import` |
| `POST` | `/networks` | server:write | API RestrictedNetwork intent/history; agent paired access/pushes | Persist active network with both assigned clients and bounded private destinations | SetAccess(present=true), SetPushRoutes where needed | Restore prior owned intent/pushes; record partial steps and reconcile | `network.create` |
| `GET` | `/networks` | server:read | API RestrictedNetwork records/filter | None | None (ListAccess during reconciliation) | None | `network.list` |
| `GET` | `/networks/{network_id}` | server:read | API RestrictedNetwork record | None | None | None | `network.read` |
| `DELETE` | `/networks/{network_id}` | server:write | API network history; agent owned access/pushes | Close active intent; already closed is idempotent | SetAccess(present=false), SetPushRoutes removing only this intent | Restore prior owned intent only if still desired; reference-count shared pushes/routes | `network.close` |
| `GET` | `/me` | authenticated | API verified principal/local User | Strict auto-registration only when current delegated-user policy permits | None | Rollback failed registration; no role/permission escalation | `principal.read` |
| `GET` | `/me/client-config` | authenticated (all three current roles) | API shared profile | None | None | Close file response on cancellation | `profile.download` |
| `GET` | `/me/clients` | authenticated + local User | API UserClient ownership filter | None | None | None | `self.client.list` |
| `GET` | `/me/devices` | authenticated + local User | API AccessGrant filter | None | None | None | `self.device.list` |
| `GET` | `/me/devices/{device_id}` | authenticated + exact AccessGrant | API granted device lookup | None | None | None | `self.device.read` |
| `PUT` | `/me/clients/{client_name}/package-cert` | authenticated + exact UserClient + active client | API self-service archive; agent generation | Record package/cache generation after ownership check | GetClient, Archive | Discard staged bytes; preserve previous valid generation | `self.certificate.package` |
| `GET` | `/me/clients/{client_name}/download-cert` | authenticated + exact UserClient + active client | API self-service archive delivery | No business change; check active ownership/generation | GetClient; Archive on cache miss | Close/cancel and discard partial staging | `self.certificate.download` |
| `POST` | `/devices` | devices:write | API DeviceService | Create device with validated optional client link | None | DB transaction rollback | `device.create` |
| `GET` | `/devices` | devices:read | API DeviceService | None | None | None | `device.list` |
| `GET` | `/devices/{device_id}` | devices:read | API DeviceService | None | None | None | `device.read` |
| `PATCH` | `/devices/{device_id}` | devices:write | API DeviceService | Update metadata/client link subject to uniqueness | None | DB transaction rollback | `device.update` |
| `DELETE` | `/devices/{device_id}` | devices:write | API DeviceService | Remove device and grants; retain VPN client | None | DB transaction rollback | `device.delete` |
| `POST` | `/users` | users:write | API UserService | Create stable issuer/subject mapping | None | DB transaction rollback | `user.create` |
| `GET` | `/users` | users:read | API UserService | None | None | None | `user.list` |
| `GET` | `/users/{user_id}` | users:read | API UserService | None | None | None | `user.read` |
| `PATCH` | `/users/{user_id}` | users:write | API UserService | Update local display name | None | DB transaction rollback | `user.update` |
| `DELETE` | `/users/{user_id}` | users:write | API UserService | Remove user/grants/client links; retain VPN clients | None | DB transaction rollback | `user.delete` |
| `PUT` | `/users/{user_id}/devices/{device_id}` | access:grant | API AccessService | Idempotently grant device access; 201 on creation | None | DB transaction rollback | `grant.ensure` |
| `DELETE` | `/users/{user_id}/devices/{device_id}` | access:grant | API AccessService | Revoke device access | None | DB transaction rollback | `grant.revoke` |
| `GET` | `/users/{user_id}/devices` | access:read | API AccessService | None | None | None | `grant.list` |
| `PUT` | `/users/{user_id}/clients/{client_id}` | users:write | API UserClientService | Exclusively link client; 201 on creation | None | DB transaction rollback | `ownership.link` |
| `DELETE` | `/users/{user_id}/clients/{client_id}` | users:write | API UserClientService | Unlink client ownership | None | DB transaction rollback | `ownership.unlink` |
| `GET` | `/users/{user_id}/clients` | users:read | API UserClientService | None | None | None | `ownership.list` |

The API read models still own users, clients, cert metadata, address allocation,
connection history and restricted-network history. Agent observations feed
reconciliation/import; they never replace business authorization. ServerConfig
projection preserves required public fields using sanitized logical markers
for agent-private paths, as specified in the protocol's compatibility section.
Profile generation preserves the current explicit remote endpoint and atomic
initialization rollback. Public certificate and shared-profile cache/download
headers, filenames, media types and size limits remain unchanged.

Background reconciliation uses Health/ServerConfig, ListClients/GetClient,
ListRoutes, ListAccess, ListSessions and LookupOperation, without creating
additional public routes. Event polling commits deduplicated history before
AckEvents and resolves gap markers through a session snapshot. Reload and exact
Disconnect are internal lifecycle/reconciliation steps, not new operator APIs.
