//! Access receipts — purpose-bound read accountability (ADR-sealed-cold-tier R1).
//!
//! Estonia/X-Road translation for kotoba: data may replicate freely (sealed,
//! R0), but a meaningful read of a non-public graph leaves a receipt — WHO
//! (DID), WHICH graph, WHAT operation, WHY (declared purpose), WHEN. Receipts
//! are datoms in the `kotoba/audit/access-receipts/v1` named graph, so they
//! are immutable, time-travel queryable, and ride the same distributed commit
//! / anchoring path as every other datom (R2 anchors their roots on Base).
//!
//! Quads emitted per receipt (subject = unique receipt CID):
//! - `(audit, r, "access/graph",        Text(target graph multibase))`
//! - `(audit, r, "access/accessor-did", Text(DID))` — CACAO leaf `iss`, else JWT `sub`; absent when anonymous
//! - `(audit, r, "access/operation",    Text(op))` — e.g. `datom:q`, `kg:entity`
//! - `(audit, r, "access/purpose",      Text(purpose))` — from `x-kotoba-purpose`
//! - `(audit, r, "access/ts-unix",      Integer(secs))`
//! - `(audit, r, "access/client-ip",    Text(ip))`     — edge-forwarded (ADR-2606131600 P0)
//! - `(audit, r, "access/user-agent",   Text(ua))`     — edge-forwarded
//! - `(audit, r, "access/request-id",   Text(reqid))`  — edge-forwarded
//!
//! ADR-2606131600 P0 (universal read audit): receipts are recorded for EVERY
//! instrumented read, **Public graphs included** (anonymous reads simply omit
//! `access/accessor-did`). With `KOTOBA_RECEIPT_STRICT=1` an un-recordable
//! receipt fails the read closed (503) instead of proceeding best-effort.
//!
//! Write path: handlers enqueue on an unbounded channel; ONE background writer
//! batches receipts (`KOTOBA_RECEIPT_FLUSH_MS`, default 1000ms / 256 receipts)
//! into a single `commit_protocol_datoms` per batch. This keeps the read hot
//! path at ~a channel send, serialises audit-graph commits (no IPNS head
//! races), and amortises the distributed-commit cost — the lesson from the
//! request-fingerprint middleware's per-request commit pileup.
//!
//! ADR-2610081200 R1 (accountability-tiered anonymity): when the gate has
//! VERIFIED that the accessor is the owner of the Private graph being read
//! (and that owner is not the operator), the receipt is still written — so the
//! hash-chained audit log and the custody cross-audit (`audit_grant`) keep
//! working — but it is [`ReceiptVisibility::OwnerOnly`]: only `access/graph`,
//! `access/operation`, `access/ts-unix` and `access/visibility "owner-only"`
//! are recorded (no accessor DID, purpose, CACAO evidence or client network
//! metadata), and the operator listing (`audit.listReceipts`) hides it. Reads
//! of someone else's data stay fully receipted and operator-visible.
//!
//! Enforcement rollout: receipts are ALWAYS recorded for Authenticated/Private
//! reads at the instrumented seams. The `x-kotoba-purpose` header becomes
//! REQUIRED for Private-graph reads only when `KOTOBA_REQUIRE_PURPOSE` is
//! truthy — observe first, enforce when clients have migrated.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use kotoba_core::cid::KotobaCid;
use kotoba_core::named_graph::GraphVisibility;
use serde::{Deserialize, Serialize};

use crate::server::KotobaState;

pub const NSID_AUDIT_LIST: &str = "com.etzhayyim.apps.kotoba.audit.listReceipts";

/// Header carrying the caller's declared purpose for a read.
pub const PURPOSE_HEADER: &str = "x-kotoba-purpose";
/// Longest stored purpose string (bytes, post-trim).
const MAX_PURPOSE_LEN: usize = 256;
/// A flush commits at most this many receipts (one tx).
const MAX_BATCH: usize = 256;

/// Named audit graph for access receipts. Fixed seed → stable across restarts
/// (same pattern as `fingerprint::audit_graph_cid`).
pub fn receipts_graph_cid() -> KotobaCid {
    KotobaCid::from_bytes(b"kotoba/audit/access-receipts/v1")
}

/// Who may see a receipt (ADR-2610081200 R1 — accountability-tiered anonymity).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ReceiptVisibility {
    /// Full receipt, listed to the operator (`audit.listReceipts`). The default,
    /// and what every receipt WITHOUT an `access/visibility` datom reads as.
    #[default]
    Operator,
    /// Owner self-access: minimal plaintext (graph / operation / ts), hidden
    /// from the operator listing. Still in the audit graph's commit chain and
    /// still matched by the custody cross-audit.
    OwnerOnly,
}

impl ReceiptVisibility {
    /// Value of the `access/visibility` datom (only emitted for `OwnerOnly`).
    pub const OWNER_ONLY_TAG: &'static str = "owner-only";
}

/// Classify a receipt. `verified_accessor` is the DID the read gate actually
/// cryptographically verified (NOT a best-effort attribution such as an
/// unverified Bearer `sub` or a decorative CACAO), so a third party can never
/// get its access hidden by merely CLAIMING to be the owner.
///
/// Self-access = Private graph whose `owner_did` equals the verified accessor.
/// Fail-safe toward recording: Public/Authenticated graphs (no owner),
/// anonymous/unverified accessors, and graphs owned by the operator itself
/// (hiding the operator's own reads from the operator protects no one) all stay
/// [`ReceiptVisibility::Operator`].
pub(crate) fn receipt_visibility_for(
    visibility: &GraphVisibility,
    verified_accessor: Option<&str>,
    operator_did: &str,
) -> ReceiptVisibility {
    match (visibility, verified_accessor) {
        (GraphVisibility::Private { owner_did }, Some(acc))
            if !owner_did.is_empty() && acc == owner_did && owner_did != operator_did =>
        {
            ReceiptVisibility::OwnerOnly
        }
        _ => ReceiptVisibility::Operator,
    }
}

/// The accessor DID that `graph_auth::check_read_access` VERIFIED when it
/// returned `Ok` for `visibility`: its Private branch only succeeds for a
/// signature-verified CACAO whose issuer IS the owner, so the owner is the
/// verified accessor. Public/Authenticated verify no DID → `None`.
pub(crate) fn check_read_access_verified_accessor(visibility: &GraphVisibility) -> Option<&str> {
    match visibility {
        GraphVisibility::Private { owner_did } => Some(owner_did.as_str()),
        _ => None,
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AccessReceipt {
    pub graph_mb: String,
    pub accessor_did: Option<String>,
    pub operation: String,
    pub purpose: Option<String>,
    pub ts_unix: u64,
    /// CID of the presented CACAO's CBOR bytes (pinned to the block store) —
    /// the requester-signed half of the two-party evidence (R2b): the receipt
    /// commit is operator-signed (author_sig), the CACAO is requester-signed.
    pub cacao_cid: Option<String>,
    /// Caller network metadata (ADR-2606131600 P0 — universal read audit). The
    /// pod sits behind the CF tunnel, so these are forwarded by the trusted edge
    /// Worker (`CF-Connecting-IP` → `x-kotoba-client-ip`, UA, request-id) and are
    /// only honoured on internally-trusted requests; a directly-reachable pod
    /// leaves them `None` (an untrusted caller cannot forge its own IP record).
    pub client_ip: Option<String>,
    pub user_agent: Option<String>,
    pub request_id: Option<String>,
    /// ADR-2610081200 R1. `#[serde(default)]` → pre-R1 data reads as Operator.
    #[serde(default)]
    pub visibility: ReceiptVisibility,
}

impl AccessReceipt {
    /// Reduce to an owner-only receipt: keep graph / operation / ts (custody
    /// cross-audit + chain integrity), drop everything that would tell the
    /// operator more than "the owner touched their own graph".
    pub fn into_owner_only(self) -> Self {
        AccessReceipt {
            graph_mb: self.graph_mb,
            operation: self.operation,
            ts_unix: self.ts_unix,
            visibility: ReceiptVisibility::OwnerOnly,
            ..Default::default()
        }
    }
}

/// Extract + sanitise the declared purpose from `x-kotoba-purpose`.
pub(crate) fn purpose_from_headers(headers: &HeaderMap) -> Option<String> {
    let raw = headers.get(PURPOSE_HEADER)?.to_str().ok()?.trim();
    if raw.is_empty() {
        return None;
    }
    let cleaned: String = raw
        .chars()
        .filter(|c| !c.is_control())
        .take(MAX_PURPOSE_LEN)
        .collect();
    if cleaned.is_empty() {
        None
    } else {
        Some(cleaned)
    }
}

/// Who is reading. Attribution follows the credential the gate actually
/// verified for this visibility tier: Private → the CACAO's leaf `iss` (its
/// signature chain was verified), falling back to the Bearer `sub`;
/// Authenticated → the Bearer `sub` FIRST, so a decorative (unverified) CACAO
/// attached to a Bearer-authed request cannot blame a third-party DID.
/// `None` only when the caller is anonymous.
pub(crate) fn accessor_from_request(
    headers: &HeaderMap,
    cacao_b64: Option<&str>,
    visibility: &GraphVisibility,
) -> Option<String> {
    let cacao_iss = || {
        let cbor = B64.decode(cacao_b64?).ok()?;
        kotoba_auth::Cacao::from_cbor(&cbor).ok().map(|c| c.p.iss)
    };
    let bearer_sub = || {
        headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .and_then(crate::graph_auth::jwt_sub)
    };
    match visibility {
        GraphVisibility::Private { .. } => cacao_iss().or_else(bearer_sub),
        _ => bearer_sub().or_else(cacao_iss),
    }
}

fn require_purpose_enabled() -> bool {
    std::env::var("KOTOBA_REQUIRE_PURPOSE")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true") || v.eq_ignore_ascii_case("on"))
        .unwrap_or(false)
}

/// Fail-closed when receipt enqueue fails (ADR-2606131600 P0). Off by default so
/// the rollout is observe-first; flip `KOTOBA_RECEIPT_STRICT=1` once the writer
/// is proven healthy and the audit trail must be unbroken.
fn receipt_strict_enabled() -> bool {
    std::env::var("KOTOBA_RECEIPT_STRICT")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true") || v.eq_ignore_ascii_case("on"))
        .unwrap_or(false)
}

/// Longest stored network-metadata string (bytes, post-trim).
const MAX_NETMETA_LEN: usize = 256;

/// Read one trusted, control-char-free header value, capped at `MAX_NETMETA_LEN`.
fn trusted_header(headers: &HeaderMap, name: &str) -> Option<String> {
    let raw = headers.get(name)?.to_str().ok()?.trim();
    if raw.is_empty() {
        return None;
    }
    let cleaned: String = raw
        .chars()
        .filter(|c| !c.is_control())
        .take(MAX_NETMETA_LEN)
        .collect();
    if cleaned.is_empty() {
        None
    } else {
        Some(cleaned)
    }
}

/// Extract caller network metadata (client IP / user-agent / request-id) for the
/// audit receipt. The pod is behind the CF tunnel and cannot observe the real
/// client socket, so these are sourced from headers the trusted edge Worker
/// forwards. They are only honoured when the request carries the internal-trust
/// secret (`require_internal_trust` passes), so a caller hitting the pod directly
/// cannot inject a forged IP into the audit log; in that case they are `None`.
pub(crate) fn client_meta_from_request(
    headers: &HeaderMap,
) -> (Option<String>, Option<String>, Option<String>) {
    if crate::graph_auth::require_internal_trust(headers).is_err() {
        return (None, None, None);
    }
    (
        trusted_header(headers, "x-kotoba-client-ip"),
        trusted_header(headers, "user-agent"),
        trusted_header(headers, "x-request-id"),
    )
}

/// Pure policy: is this (visibility, purpose) pair a violation under `enforce`?
fn purpose_violation(visibility: &GraphVisibility, purpose: Option<&str>, enforce: bool) -> bool {
    enforce && matches!(visibility, GraphVisibility::Private { .. }) && purpose.is_none()
}

/// Post-auth hook for instrumented read seams: enforce the purpose policy and
/// enqueue a receipt.
///
/// ADR-2606131600 P0 (universal read audit): EVERY non-trivial read — Public
/// included — leaves a receipt now, so "who read which data" is provable for the
/// whole surface, not just non-public graphs. Public reads simply carry no
/// `accessor_did` (anonymous), but still record graph / operation / ts and any
/// forwarded client IP / user-agent / request-id. The purpose-required policy
/// remains Private-only.
///
/// `verified_accessor` is the DID the caller's gate cryptographically verified
/// (see [`receipt_visibility_for`]); when it is the Private graph's owner the
/// receipt is recorded [`ReceiptVisibility::OwnerOnly`] (ADR-2610081200 R1).
pub(crate) fn enforce_and_record(
    state: &KotobaState,
    headers: &HeaderMap,
    cacao_b64: Option<&str>,
    graph: &KotobaCid,
    visibility: &GraphVisibility,
    operation: &str,
    verified_accessor: Option<&str>,
) -> Result<(), (StatusCode, String)> {
    let purpose = purpose_from_headers(headers);
    if purpose_violation(visibility, purpose.as_deref(), require_purpose_enabled()) {
        return Err((
            StatusCode::BAD_REQUEST,
            format!(
                "{PURPOSE_HEADER} header required: private-graph reads must declare a purpose \
                 (KOTOBA_REQUIRE_PURPOSE is on; ADR-sealed-cold-tier R1)"
            ),
        ));
    }
    let ts_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let receipt = match receipt_visibility_for(visibility, verified_accessor, &state.operator_did) {
        // ADR-2610081200 R1: owner self-access — minimal receipt. The CACAO is
        // NOT pinned as evidence and no client metadata / purpose is read into
        // the record (nothing the operator should learn).
        ReceiptVisibility::OwnerOnly => AccessReceipt {
            graph_mb: graph.to_multibase(),
            operation: operation.to_string(),
            ts_unix,
            ..Default::default()
        }
        .into_owner_only(),
        ReceiptVisibility::Operator => {
            // Pin the presented CACAO bytes as requester-signed evidence (only
            // when they actually parse — garbage would not have passed a
            // Private gate).
            let cacao_cid = pin_cacao_evidence(state, cacao_b64);
            let (client_ip, user_agent, request_id) = client_meta_from_request(headers);
            AccessReceipt {
                graph_mb: graph.to_multibase(),
                accessor_did: accessor_from_request(headers, cacao_b64, visibility),
                operation: operation.to_string(),
                purpose,
                ts_unix,
                cacao_cid,
                client_ip,
                user_agent,
                request_id,
                visibility: ReceiptVisibility::Operator,
            }
        }
    };
    if state.receipt_tx.send(receipt).is_err() {
        // Writer task gone (shutdown or never spawned outside a runtime).
        // ADR-2606131600 P0: under KOTOBA_RECEIPT_STRICT the audit trail is a
        // hard precondition — refuse the read rather than let it go unrecorded.
        // Default (strict off) stays best-effort: the read proceeds, loudly.
        if receipt_strict_enabled() {
            tracing::error!(graph = %graph.to_multibase(), operation, "access receipt UNRECORDABLE — refusing read (KOTOBA_RECEIPT_STRICT)");
            return Err((
                StatusCode::SERVICE_UNAVAILABLE,
                "read audit unavailable: receipt could not be recorded (KOTOBA_RECEIPT_STRICT)"
                    .to_string(),
            ));
        }
        tracing::warn!(graph = %graph.to_multibase(), operation, "access receipt DROPPED — writer unavailable");
    }
    Ok(())
}

/// Enqueue a pre-built receipt (used by seams that aren't a plain HTTP read —
/// e.g. the custodian key-share protocol builds its own AccessReceipt with the
/// CACAO already verified). Best-effort, same as `enforce_and_record`.
pub(crate) fn record_receipt(state: &KotobaState, receipt: AccessReceipt) {
    let op = receipt.operation.clone();
    if state.receipt_tx.send(receipt).is_err() {
        tracing::warn!(operation = %op, "access receipt DROPPED — writer unavailable");
    }
}

/// Pin presented CACAO bytes to the block store, returning their CID multibase
/// (the requester-signed evidence half). `None` if absent or unparseable.
pub(crate) fn pin_cacao_evidence(state: &KotobaState, cacao_b64: Option<&str>) -> Option<String> {
    cacao_b64
        .and_then(|b64| B64.decode(b64).ok())
        .filter(|cbor| kotoba_auth::Cacao::from_cbor(cbor).is_ok())
        .map(|cbor| {
            let cid = KotobaCid::from_bytes(&cbor);
            if let Err(e) = state.block_store.put(&cid, &cbor) {
                tracing::warn!(err = %e, "cacao evidence block put failed");
            }
            cid.to_multibase()
        })
}

/// Unique receipt subject CID: content fields + a process-monotonic counter so
/// two reads in the same second never collide.
fn receipt_cid(r: &AccessReceipt, seq: u64) -> KotobaCid {
    let mut buf = Vec::with_capacity(r.graph_mb.len() + 64);
    buf.extend_from_slice(r.graph_mb.as_bytes());
    buf.push(b'|');
    buf.extend_from_slice(r.accessor_did.as_deref().unwrap_or("").as_bytes());
    buf.push(b'|');
    buf.extend_from_slice(r.operation.as_bytes());
    buf.push(b'|');
    buf.extend_from_slice(&r.ts_unix.to_le_bytes());
    buf.push(b'|');
    buf.extend_from_slice(&seq.to_le_bytes());
    if r.visibility == ReceiptVisibility::OwnerOnly {
        buf.push(b'|');
        buf.extend_from_slice(ReceiptVisibility::OWNER_ONLY_TAG.as_bytes());
    }
    KotobaCid::from_bytes(&buf)
}

pub(crate) fn build_receipt_datoms(
    r: &AccessReceipt,
    subject: &KotobaCid,
    tx_cid: &KotobaCid,
) -> Vec<kotoba_datomic::Datom> {
    let mut datoms = vec![
        kotoba_datomic::Datom::assert(
            subject.clone(),
            "access/graph".to_string(),
            kotoba_edn::EdnValue::string(&r.graph_mb),
            tx_cid.clone(),
        ),
        kotoba_datomic::Datom::assert(
            subject.clone(),
            "access/operation".to_string(),
            kotoba_edn::EdnValue::string(&r.operation),
            tx_cid.clone(),
        ),
        kotoba_datomic::Datom::assert(
            subject.clone(),
            "access/ts-unix".to_string(),
            kotoba_edn::EdnValue::Integer(r.ts_unix as i64),
            tx_cid.clone(),
        ),
    ];
    // ADR-2610081200 R1: an owner-only receipt carries ONLY graph / operation /
    // ts + the visibility marker — enforced here too (defence in depth), even
    // if a caller forgot `into_owner_only`. The marker datom is part of the
    // commit, so the audit chain's author_sig covers the visibility claim.
    if r.visibility == ReceiptVisibility::OwnerOnly {
        datoms.push(kotoba_datomic::Datom::assert(
            subject.clone(),
            "access/visibility".to_string(),
            kotoba_edn::EdnValue::string(ReceiptVisibility::OWNER_ONLY_TAG),
            tx_cid.clone(),
        ));
        return datoms;
    }
    if let Some(did) = &r.accessor_did {
        datoms.push(kotoba_datomic::Datom::assert(
            subject.clone(),
            "access/accessor-did".to_string(),
            kotoba_edn::EdnValue::string(did),
            tx_cid.clone(),
        ));
    }
    if let Some(purpose) = &r.purpose {
        datoms.push(kotoba_datomic::Datom::assert(
            subject.clone(),
            "access/purpose".to_string(),
            kotoba_edn::EdnValue::string(purpose),
            tx_cid.clone(),
        ));
    }
    if let Some(cacao_cid) = &r.cacao_cid {
        datoms.push(kotoba_datomic::Datom::assert(
            subject.clone(),
            "access/cacao-cid".to_string(),
            kotoba_edn::EdnValue::string(cacao_cid),
            tx_cid.clone(),
        ));
    }
    // Caller network metadata (ADR-2606131600 P0). Forwarded by the trusted edge
    // Worker; absent for direct-pod / dev callers.
    if let Some(ip) = &r.client_ip {
        datoms.push(kotoba_datomic::Datom::assert(
            subject.clone(),
            "access/client-ip".to_string(),
            kotoba_edn::EdnValue::string(ip),
            tx_cid.clone(),
        ));
    }
    if let Some(ua) = &r.user_agent {
        datoms.push(kotoba_datomic::Datom::assert(
            subject.clone(),
            "access/user-agent".to_string(),
            kotoba_edn::EdnValue::string(ua),
            tx_cid.clone(),
        ));
    }
    if let Some(rid) = &r.request_id {
        datoms.push(kotoba_datomic::Datom::assert(
            subject.clone(),
            "access/request-id".to_string(),
            kotoba_edn::EdnValue::string(rid),
            tx_cid.clone(),
        ));
    }
    datoms
}

static RECEIPT_SEQ: AtomicU64 = AtomicU64::new(0);

/// Commit one batch of receipts as a single audit-graph tx.
pub(crate) async fn write_receipt_batch(state: &KotobaState, batch: Vec<AccessReceipt>) {
    if batch.is_empty() {
        return;
    }
    let graph = receipts_graph_cid();
    let first_seq = RECEIPT_SEQ.fetch_add(batch.len() as u64, Ordering::Relaxed);
    let tx_cid = KotobaCid::from_bytes(
        format!(
            "access.receipt.tx:{}:{}:{}",
            batch[0].ts_unix,
            first_seq,
            batch.len()
        )
        .as_bytes(),
    );
    let mut datoms = Vec::with_capacity(batch.len() * 5);
    let mut first_subject: Option<KotobaCid> = None;
    for (i, r) in batch.iter().enumerate() {
        let subject = receipt_cid(r, first_seq + i as u64);
        if first_subject.is_none() {
            first_subject = Some(subject.clone());
        }
        datoms.extend(build_receipt_datoms(r, &subject, &tx_cid));
    }
    let entity = first_subject.expect("non-empty batch");
    if let Err((status, message)) = crate::xrpc::commit_protocol_datoms(
        state,
        graph.clone(),
        graph.to_multibase(),
        entity,
        datoms,
        tx_cid,
        state.operator_did.clone(),
        kotoba_auth::CacaoPayload::OP_DATOM_TRANSACT,
        None,
        None,
    )
    .await
    {
        // Best-effort in R1 (same stance as request fingerprints): the
        // underlying read already happened; receipts harden to fail-closed
        // with the R2 signed-journal path.
        tracing::warn!(status = %status, error = %message, "access receipt batch commit failed");
    }
}

/// Start the single background receipt writer. Idempotent (the receiver can be
/// taken once); a no-op outside a tokio runtime (sync test contexts).
pub fn spawn_receipt_writer(state: Arc<KotobaState>) {
    if tokio::runtime::Handle::try_current().is_err() {
        tracing::warn!("access-receipt writer not started: no tokio runtime");
        return;
    }
    let Some(mut rx) = state.receipt_rx.lock().unwrap().take() else {
        return; // already running
    };
    let flush_ms: u64 = std::env::var("KOTOBA_RECEIPT_FLUSH_MS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(1000);
    tokio::spawn(async move {
        loop {
            // Block until the first receipt of a batch arrives…
            let Some(first) = rx.recv().await else { break };
            let mut batch = vec![first];
            // …drain whatever is already queued (no waiting) so a backlog from
            // a slow commit clears at full speed instead of MAX_BATCH/window…
            while batch.len() < MAX_BATCH {
                match rx.try_recv() {
                    Ok(r) => batch.push(r),
                    Err(_) => break,
                }
            }
            // …then, if there is room, collect stragglers for one flush window.
            if batch.len() < MAX_BATCH {
                let deadline = tokio::time::sleep(std::time::Duration::from_millis(flush_ms));
                tokio::pin!(deadline);
                loop {
                    tokio::select! {
                        _ = &mut deadline => break,
                        more = rx.recv() => match more {
                            Some(r) => {
                                batch.push(r);
                                if batch.len() >= MAX_BATCH {
                                    break;
                                }
                            }
                            None => break,
                        },
                    }
                }
            }
            write_receipt_batch(&state, batch).await;
        }
        tracing::info!("access-receipt writer stopped (channel closed)");
    });
}

// ── audit.listReceipts XRPC ──────────────────────────────────────────────────

#[derive(Debug, Default, Deserialize)]
pub struct AuditListQuery {
    /// Filter: target graph multibase CID.
    pub graph: Option<String>,
    /// Filter: accessor DID.
    pub accessor: Option<String>,
    /// Max receipts returned (default 100, cap 1000).
    pub limit: Option<usize>,
}

/// GET /xrpc/com.etzhayyim.apps.kotoba.audit.listReceipts
///
/// Operator-gated in R1 (the owner-facing CACAO gate — Estonia's citizen Data
/// Tracker analog — lands with per-graph keys, where owner != operator becomes
/// the common case). ADR-2610081200 R1: owner-only receipts (owner self-access)
/// are EXCLUDED from this operator listing.
pub async fn audit_list_receipts(
    State(state): State<Arc<KotobaState>>,
    headers: HeaderMap,
    Query(q): Query<AuditListQuery>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    crate::graph_auth::require_operator_auth(&headers, &state.operator_did)?;

    let graph = receipts_graph_cid();
    let quads = state
        .quad_store
        .quads_by_predicate_prefix(Some(&graph), "access/")
        .await;
    let receipts = operator_visible_receipts(&quads, &q);

    Ok(Json(serde_json::json!({
        "ok": true,
        "count": receipts.len(),
        "receipts": receipts,
    })))
}

/// Project audit-graph quads into the operator listing: group by receipt
/// subject, DROP owner-only receipts (ADR-2610081200 R1), apply the
/// graph/accessor filters, newest first, truncated to the limit.
pub(crate) fn operator_visible_receipts(
    quads: &[kotoba_query::quad::LegacyQuad],
    q: &AuditListQuery,
) -> Vec<serde_json::Value> {
    use std::collections::HashMap;
    let limit = q.limit.unwrap_or(100).min(1000);
    let mut by_subject: HashMap<String, serde_json::Map<String, serde_json::Value>> =
        HashMap::new();
    for quad in quads {
        let entry = by_subject.entry(quad.subject.to_multibase()).or_default();
        let value: serde_json::Value = match &quad.object {
            kotoba_query::quad::LegacyQuadObject::Text(s) => s.clone().into(),
            kotoba_query::quad::LegacyQuadObject::Integer(i) => (*i).into(),
            other => format!("{other:?}").into(),
        };
        let key = match quad.predicate.as_str() {
            "access/graph" => "graph",
            "access/accessor-did" => "accessorDid",
            "access/operation" => "operation",
            "access/purpose" => "purpose",
            "access/cacao-cid" => "cacaoCid",
            "access/ts-unix" => "tsUnix",
            "access/client-ip" => "clientIp",
            "access/user-agent" => "userAgent",
            "access/request-id" => "requestId",
            "access/visibility" => "visibility",
            _ => continue,
        };
        entry.insert(key.to_string(), value);
    }

    let mut receipts: Vec<serde_json::Value> = by_subject
        .into_iter()
        .filter(|(_, fields)| {
            // ADR-2610081200 R1: owner self-access is not the operator's business.
            if fields.get("visibility").and_then(|v| v.as_str())
                == Some(ReceiptVisibility::OWNER_ONLY_TAG)
            {
                return false;
            }
            if let Some(g) = &q.graph {
                if fields.get("graph").and_then(|v| v.as_str()) != Some(g.as_str()) {
                    return false;
                }
            }
            if let Some(a) = &q.accessor {
                if fields.get("accessorDid").and_then(|v| v.as_str()) != Some(a.as_str()) {
                    return false;
                }
            }
            true
        })
        .map(|(cid, mut fields)| {
            fields.insert("receiptCid".to_string(), cid.into());
            serde_json::Value::Object(fields)
        })
        .collect();
    receipts
        .sort_by_key(|r| std::cmp::Reverse(r.get("tsUnix").and_then(|v| v.as_i64()).unwrap_or(0)));
    receipts.truncate(limit);
    receipts
}

// ── audit.verifyChain XRPC (R2b — operator-side tamper check) ────────────────

pub const NSID_AUDIT_VERIFY: &str = "com.etzhayyim.apps.kotoba.audit.verifyChain";

#[derive(Debug, Deserialize)]
pub struct AuditVerifyQuery {
    /// Max commits to walk back from the head (default 100, cap 10_000).
    pub limit: Option<usize>,
}

/// GET /xrpc/com.etzhayyim.apps.kotoba.audit.verifyChain
///
/// Walks the audit graph's CommitDag from the IPNS head along `prev`,
/// verifying each commit's `author_sig` against its author DID. One call
/// answers "has anyone rewritten the receipt log?" — pair with the on-chain
/// anchor (audit.anchorPayload) for the operator-can't-cheat half.
pub async fn audit_verify_chain(
    State(state): State<Arc<KotobaState>>,
    headers: HeaderMap,
    Query(q): Query<AuditVerifyQuery>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    crate::graph_auth::require_operator_auth(&headers, &state.operator_did)?;

    let limit = q.limit.unwrap_or(100).min(10_000);
    let graph = receipts_graph_cid();
    let ipns_name = crate::xrpc::distributed_graph_ipns_name(&graph);
    let record = state
        .ipns_registry
        .resolve(&kotoba_ipfs::IpnsName::new(ipns_name))
        .map_err(|e| match e {
            kotoba_ipfs::IpnsRegistryError::NotFound(_) => (
                StatusCode::NOT_FOUND,
                "no receipts committed yet — nothing to verify".to_string(),
            ),
            other => (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("ipns resolve: {other}"),
            ),
        })?;
    let mut cursor = KotobaCid::from_multibase(&record.value);

    let (mut depth, mut valid, mut unsigned, mut unverifiable) = (0usize, 0usize, 0usize, 0usize);
    let mut invalid: Vec<String> = Vec::new();
    while let Some(cid) = cursor.take() {
        if depth >= limit {
            break;
        }
        let commit =
            kotoba_datomic::distributed::DistributedDatomCommit::load(&cid, &*state.block_store)
                .map_err(|e| {
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        format!("commit load: {e}"),
                    )
                })?
                .ok_or((
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("commit block missing: {}", cid.to_multibase()),
                ))?;
        match kotoba_auth::verify_commit_author_sig(&commit) {
            kotoba_auth::CommitSigVerdict::Valid => valid += 1,
            kotoba_auth::CommitSigVerdict::Unsigned => unsigned += 1,
            kotoba_auth::CommitSigVerdict::Unverifiable(_) => unverifiable += 1,
            kotoba_auth::CommitSigVerdict::Invalid => invalid.push(cid.to_multibase()),
        }
        depth += 1;
        cursor = commit.prev.clone();
    }

    Ok(Json(serde_json::json!({
        "ok": invalid.is_empty(),
        "graph": graph.to_multibase(),
        "depth": depth,
        "valid": valid,
        "unsigned": unsigned,
        "unverifiable": unverifiable,
        "invalid": invalid,
    })))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn receipt() -> AccessReceipt {
        AccessReceipt {
            graph_mb: "btestgraph".into(),
            accessor_did: Some("did:key:zReader".into()),
            operation: "datom:q".into(),
            purpose: Some("billing-dispute #42".into()),
            ts_unix: 1_780_000_000,
            cacao_cid: None,
            ..Default::default()
        }
    }

    #[test]
    fn receipts_graph_cid_is_stable() {
        assert_eq!(receipts_graph_cid().0, receipts_graph_cid().0);
        assert_ne!(
            receipts_graph_cid().0,
            KotobaCid::from_bytes(b"kotoba/audit/requests/v1").0,
            "must not collide with the request-fingerprint graph"
        );
    }

    #[test]
    fn purpose_header_trimmed_capped_and_control_stripped() {
        let mut h = HeaderMap::new();
        // \t is a control char that HeaderValue accepts — the filter strips it.
        h.insert(PURPOSE_HEADER, "  billing\taudit  ".parse().unwrap());
        assert_eq!(purpose_from_headers(&h).as_deref(), Some("billingaudit"));

        let mut h = HeaderMap::new();
        h.insert(PURPOSE_HEADER, "   ".parse().unwrap());
        assert_eq!(purpose_from_headers(&h), None, "whitespace-only → None");

        let long = "p".repeat(MAX_PURPOSE_LEN + 50);
        let mut h = HeaderMap::new();
        h.insert(PURPOSE_HEADER, long.parse().unwrap());
        assert_eq!(purpose_from_headers(&h).unwrap().len(), MAX_PURPOSE_LEN);

        assert_eq!(purpose_from_headers(&HeaderMap::new()), None);
    }

    #[test]
    fn accessor_falls_back_to_jwt_sub() {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let payload = URL_SAFE_NO_PAD.encode(br#"{"sub":"did:key:zJwtCaller","exp":9999999999}"#);
        let token = format!("eyJhbGciOiJub25lIn0.{payload}.sig");
        let mut h = HeaderMap::new();
        h.insert(
            axum::http::header::AUTHORIZATION,
            format!("Bearer {token}").parse().unwrap(),
        );
        let auth_tier = GraphVisibility::Authenticated;
        assert_eq!(
            accessor_from_request(&h, None, &auth_tier).as_deref(),
            Some("did:key:zJwtCaller")
        );
        assert_eq!(
            accessor_from_request(&HeaderMap::new(), None, &auth_tier),
            None
        );
    }

    #[test]
    fn purpose_policy_only_bites_private_under_enforcement() {
        let private = GraphVisibility::Private {
            owner_did: "did:key:zOwner".into(),
        };
        assert!(purpose_violation(&private, None, true));
        assert!(!purpose_violation(&private, Some("ops"), true));
        assert!(
            !purpose_violation(&private, None, false),
            "observe-only default"
        );
        assert!(!purpose_violation(
            &GraphVisibility::Authenticated,
            None,
            true
        ));
        assert!(!purpose_violation(&GraphVisibility::Public, None, true));
    }

    #[test]
    fn receipt_datoms_carry_all_fields() {
        let mut r = receipt();
        r.cacao_cid = Some("bcacaoevidence".into());
        r.client_ip = Some("203.0.113.7".into());
        r.user_agent = Some("kotoba-cli/0.1".into());
        r.request_id = Some("req-abc123".into());
        let subject = receipt_cid(&r, 1);
        let tx = KotobaCid::from_bytes(b"tx");
        let datoms = build_receipt_datoms(&r, &subject, &tx);
        let attrs: Vec<&str> = datoms.iter().map(|d| d.a.as_str()).collect();
        assert_eq!(
            attrs,
            vec![
                "access/graph",
                "access/operation",
                "access/ts-unix",
                "access/accessor-did",
                "access/purpose",
                "access/cacao-cid",
                "access/client-ip",
                "access/user-agent",
                "access/request-id",
            ]
        );
        assert!(datoms.iter().all(|d| d.t == tx && d.added));
    }

    #[test]
    fn anonymous_public_read_still_records_a_receipt_sans_did() {
        // ADR-2606131600 P0: a Public-graph read with no credential is recorded
        // (graph/operation/ts) but carries no accessor-did.
        let r = AccessReceipt {
            graph_mb: "bpublicgraph".into(),
            accessor_did: None,
            operation: "datom:q".into(),
            purpose: None,
            ts_unix: 1_780_000_999,
            ..Default::default()
        };
        let subject = receipt_cid(&r, 7);
        let tx = KotobaCid::from_bytes(b"tx");
        let datoms = build_receipt_datoms(&r, &subject, &tx);
        let attrs: Vec<&str> = datoms.iter().map(|d| d.a.as_str()).collect();
        assert!(attrs.contains(&"access/graph"));
        assert!(attrs.contains(&"access/operation"));
        assert!(attrs.contains(&"access/ts-unix"));
        assert!(
            !attrs.contains(&"access/accessor-did"),
            "anonymous read must not fabricate an accessor DID"
        );
    }

    #[test]
    fn client_meta_ignored_without_internal_trust() {
        // Network metadata is only honoured behind the trusted edge. With
        // KOTOBA_INTERNAL_SECRET set and absent on the request, forged IP headers
        // are dropped. (When the secret is unset, require_internal_trust is a
        // no-op by design — dev/back-compat — so this asserts the gated path.)
        std::env::set_var("KOTOBA_INTERNAL_SECRET", "s3cr3t-test");
        let mut h = HeaderMap::new();
        h.insert("x-kotoba-client-ip", "203.0.113.7".parse().unwrap());
        h.insert("user-agent", "evil/1.0".parse().unwrap());
        let (ip, ua, rid) = client_meta_from_request(&h);
        assert_eq!(ip, None, "untrusted IP header must be ignored");
        assert_eq!(ua, None);
        assert_eq!(rid, None);
        std::env::remove_var("KOTOBA_INTERNAL_SECRET");
    }

    #[test]
    fn anonymous_no_purpose_receipt_has_three_datoms() {
        let r = AccessReceipt {
            accessor_did: None,
            purpose: None,
            ..receipt()
        };
        let subject = receipt_cid(&r, 2);
        let datoms = build_receipt_datoms(&r, &subject, &KotobaCid::from_bytes(b"tx"));
        assert_eq!(datoms.len(), 3);
    }

    #[test]
    fn receipt_cids_unique_per_seq_and_deterministic() {
        let r = receipt();
        assert_ne!(receipt_cid(&r, 1).0, receipt_cid(&r, 2).0);
        assert_eq!(receipt_cid(&r, 7).0, receipt_cid(&r, 7).0);
    }
}

#[cfg(test)]
mod write_path_tests {
    use super::*;

    #[tokio::test(flavor = "multi_thread")]
    async fn write_receipt_batch_lands_in_hot_arrangement() {
        std::env::set_var("KOTOBA_IPFS", "off");
        let state = crate::server::KotobaState::new(None).expect("state");
        let r = AccessReceipt {
            graph_mb: "btarget".into(),
            accessor_did: Some("did:key:zU".into()),
            operation: "datom:q".into(),
            purpose: Some("unit".into()),
            ts_unix: 1_780_000_123,
            cacao_cid: None,
            ..Default::default()
        };
        write_receipt_batch(&state, vec![r]).await;
        let quads = state
            .quad_store
            .quads_by_predicate_prefix(Some(&receipts_graph_cid()), "access/")
            .await;
        eprintln!("quads with access/ prefix: {}", quads.len());
        let all = state
            .quad_store
            .quads_by_predicate_prefix(Some(&receipts_graph_cid()), "")
            .await;
        for q in all.iter().take(12) {
            eprintln!("  attr={} obj={:?}", q.predicate, q.object);
        }
        assert!(
            quads.iter().any(|q| q.predicate == "access/purpose"),
            "receipt datoms must be queryable in the hot arrangement"
        );
    }
}

#[cfg(test)]
mod writer_task_tests {
    use super::*;

    // current_thread flavor on purpose: reproduces the e2e harness runtime.
    #[tokio::test]
    async fn channel_writer_flushes_on_current_thread_runtime() {
        std::env::set_var("KOTOBA_IPFS", "off");
        std::env::set_var("KOTOBA_RECEIPT_FLUSH_MS", "20");
        let state = Arc::new(crate::server::KotobaState::new(None).expect("state"));
        spawn_receipt_writer(Arc::clone(&state));
        state
            .receipt_tx
            .send(AccessReceipt {
                graph_mb: "btarget".into(),
                accessor_did: Some("did:key:zCt".into()),
                operation: "kg:catalog".into(),
                purpose: Some("ct".into()),
                ts_unix: 1_780_000_456,
                cacao_cid: None,
                ..Default::default()
            })
            .expect("send");
        for _ in 0..50 {
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            let quads = state
                .quad_store
                .quads_by_predicate_prefix(Some(&receipts_graph_cid()), "access/operation")
                .await;
            if !quads.is_empty() {
                return;
            }
        }
        panic!("receipt never flushed on current_thread runtime");
    }
}

#[cfg(test)]
mod attribution_tests {
    use super::*;

    fn bearer(did: &str) -> HeaderMap {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let payload =
            URL_SAFE_NO_PAD.encode(format!(r#"{{"sub":"{did}","exp":9999999999}}"#).as_bytes());
        let mut h = HeaderMap::new();
        h.insert(
            axum::http::header::AUTHORIZATION,
            format!("Bearer eyJhbGciOiJub25lIn0.{payload}.sig")
                .parse()
                .unwrap(),
        );
        h
    }

    #[test]
    fn authenticated_tier_prefers_bearer_over_decorative_cacao() {
        // An unverified CACAO attached to a Bearer-authed read must not be able
        // to attribute the access to a third-party DID.
        let h = bearer("did:key:zRealCaller");
        let bogus_cacao = base64::engine::general_purpose::STANDARD.encode(b"not-a-real-cacao");
        let got = accessor_from_request(&h, Some(&bogus_cacao), &GraphVisibility::Authenticated);
        assert_eq!(got.as_deref(), Some("did:key:zRealCaller"));
    }

    #[test]
    fn private_tier_falls_back_to_bearer_when_cacao_unparseable() {
        let h = bearer("did:key:zFallback");
        let got = accessor_from_request(
            &h,
            Some("%%%not-base64%%%"),
            &GraphVisibility::Private {
                owner_did: "did:key:zOwner".into(),
            },
        );
        assert_eq!(got.as_deref(), Some("did:key:zFallback"));
    }
}

// ── audit.anchorPayload XRPC (R2a — receipt-root anchoring) ──────────────────

pub const NSID_AUDIT_ANCHOR: &str = "com.etzhayyim.apps.kotoba.audit.anchorPayload";

/// GET /xrpc/com.etzhayyim.apps.kotoba.audit.anchorPayload
///
/// The Estonia-KSI analog: returns the `AnchorBridge.commitRoot(bytes32,bytes,
/// uint64)` calldata committing the audit graph's CURRENT head commit CID to
/// Base. kotoba builds the payload; the relayer signs + submits (the same
/// read+verify boundary as kotoba-EVM R3, ADR-2606091500 / PR #96). Once the
/// root is on-chain, not even the node operator can silently rewrite or drop
/// receipts committed before the anchor.
///
/// `rootHash` = low 32 bytes of the head commit CID; `ipfsCid` = the head CID
/// multibase (anyone can fetch + replay the audit DAG from IPFS and check it
/// hashes to the anchored root); `batchSize` = the IPNS sequence (monotonic
/// commit count for the audit graph).
pub async fn audit_anchor_payload(
    State(state): State<Arc<KotobaState>>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    crate::graph_auth::require_operator_auth(&headers, &state.operator_did)?;

    let graph = receipts_graph_cid();
    let ipns_name = crate::xrpc::distributed_graph_ipns_name(&graph);
    let record = state
        .ipns_registry
        .resolve(&kotoba_ipfs::IpnsName::new(ipns_name))
        .map_err(|e| match e {
            kotoba_ipfs::IpnsRegistryError::NotFound(_) => (
                StatusCode::NOT_FOUND,
                "no receipts committed yet — nothing to anchor".to_string(),
            ),
            other => (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("ipns resolve: {other}"),
            ),
        })?;
    let head = KotobaCid::from_multibase(&record.value).ok_or((
        StatusCode::INTERNAL_SERVER_ERROR,
        format!("audit head is not a CID: {}", record.value),
    ))?;
    let calldata = kotoba_evm::anchor::anchor_block_calldata(&head, &head, record.sequence);

    Ok(Json(serde_json::json!({
        "ok": true,
        "graph": graph.to_multibase(),
        "headCid": head.to_multibase(),
        "seq": record.sequence,
        "function": "commitRoot(bytes32,bytes,uint64)",
        "calldataHex": hex::encode(&calldata),
    })))
}

#[cfg(test)]
mod anchor_tests {
    use super::*;

    #[tokio::test(flavor = "multi_thread")]
    async fn anchor_payload_encodes_committed_audit_head() {
        std::env::set_var("KOTOBA_IPFS", "off");
        let state = crate::server::KotobaState::new(None).expect("state");

        // Before any receipt: head missing.
        let ipns = crate::xrpc::distributed_graph_ipns_name(&receipts_graph_cid());
        assert!(state
            .ipns_registry
            .resolve(&kotoba_ipfs::IpnsName::new(ipns.clone()))
            .is_err());

        // Commit one receipt batch → audit head exists.
        write_receipt_batch(
            &state,
            vec![AccessReceipt {
                graph_mb: "btarget".into(),
                accessor_did: Some("did:key:zA".into()),
                operation: "datom:q".into(),
                purpose: Some("anchor-test".into()),
                ts_unix: 1_780_000_789,
                cacao_cid: None,
                ..Default::default()
            }],
        )
        .await;
        let record = state
            .ipns_registry
            .resolve(&kotoba_ipfs::IpnsName::new(ipns))
            .expect("audit head after first batch");
        let head = KotobaCid::from_multibase(&record.value).expect("head CID");

        // The calldata layout matches kotoba-evm's pinned ABI: selector, then
        // rootHash = low 32 bytes of the head CID.
        let calldata = kotoba_evm::anchor::anchor_block_calldata(&head, &head, record.sequence);
        assert_eq!(&calldata[..4], &kotoba_evm::anchor::commit_root_selector());
        assert_eq!(&calldata[4..36], &head.0[4..36]);
        // dynamic tail carries the multibase CID string.
        let mb = head.to_multibase();
        assert!(calldata.windows(mb.len()).any(|w| w == mb.as_bytes()));
    }
}

#[cfg(test)]
mod signed_commit_tests {
    use super::*;

    /// R2b: the audit-graph head commit is author-signed by the operator and
    /// verifiable from the author DID alone (did:key → pubkey → verify).
    #[tokio::test(flavor = "multi_thread")]
    async fn receipt_commit_is_author_signed_and_did_verifiable() {
        std::env::set_var("KOTOBA_IPFS", "off");
        let state = crate::server::KotobaState::new(None).expect("state");
        write_receipt_batch(
            &state,
            vec![AccessReceipt {
                graph_mb: "btarget".into(),
                accessor_did: Some("did:key:zR2b".into()),
                operation: "datom:q".into(),
                purpose: Some("sig-test".into()),
                ts_unix: 1_780_001_000,
                cacao_cid: None,
                ..Default::default()
            }],
        )
        .await;
        let ipns = crate::xrpc::distributed_graph_ipns_name(&receipts_graph_cid());
        let record = state
            .ipns_registry
            .resolve(&kotoba_ipfs::IpnsName::new(ipns))
            .expect("audit head");
        let head = KotobaCid::from_multibase(&record.value).expect("head CID");
        let commit =
            kotoba_datomic::distributed::DistributedDatomCommit::load(&head, &*state.block_store)
                .expect("load")
                .expect("commit block");
        assert_eq!(commit.author, state.operator_did);
        assert!(commit.author_sig.is_some(), "audit commit must be signed");
        // Verify with the node key…
        let vk = state.operator_signing_key().verifying_key();
        assert!(commit.verify_author_sig(&vk).unwrap());
        // …and via the author DID alone (what a third-party verifier does).
        if commit.author.starts_with("did:key:") {
            let pk = kotoba_auth::parse_ed25519_did_key(&commit.author).expect("did:key");
            let vk2 = ed25519_dalek::VerifyingKey::from_bytes(&pk).expect("pubkey");
            assert!(commit.verify_author_sig(&vk2).unwrap());
        }
    }

    /// R2b: verify_commit_author_sig over the whole audit chain — two batches
    /// → two commits, both Valid when the operator DID is did:key.
    #[tokio::test(flavor = "multi_thread")]
    async fn audit_chain_walk_verifies_every_commit() {
        std::env::set_var("KOTOBA_IPFS", "off");
        let state = crate::server::KotobaState::new(None).expect("state");
        for i in 0..2u64 {
            write_receipt_batch(
                &state,
                vec![AccessReceipt {
                    graph_mb: "btarget".into(),
                    accessor_did: Some(format!("did:key:zWalk{i}")),
                    operation: "datom:q".into(),
                    purpose: None,
                    ts_unix: 1_780_002_000 + i,
                    cacao_cid: None,
                    ..Default::default()
                }],
            )
            .await;
        }
        let ipns = crate::xrpc::distributed_graph_ipns_name(&receipts_graph_cid());
        let record = state
            .ipns_registry
            .resolve(&kotoba_ipfs::IpnsName::new(ipns))
            .expect("head");
        let mut cursor = KotobaCid::from_multibase(&record.value);
        let mut depth = 0;
        let did_key_operator = state.operator_did.starts_with("did:key:");
        while let Some(cid) = cursor.take() {
            let commit = kotoba_datomic::distributed::DistributedDatomCommit::load(
                &cid,
                &*state.block_store,
            )
            .unwrap()
            .unwrap();
            let verdict = kotoba_auth::verify_commit_author_sig(&commit);
            if did_key_operator {
                assert_eq!(
                    verdict,
                    kotoba_auth::CommitSigVerdict::Valid,
                    "depth {depth}"
                );
            } else {
                assert!(matches!(
                    verdict,
                    kotoba_auth::CommitSigVerdict::Unverifiable(_)
                ));
            }
            depth += 1;
            cursor = commit.prev.clone();
        }
        assert_eq!(depth, 2, "two batches → two commits");
    }
}

// ── ADR-2610081200 R1 — owner-only receipts (accountability-tiered anonymity) ─

#[cfg(test)]
mod owner_only_tests {
    use super::*;

    const OWNER: &str = "did:key:zGraphOwner";
    const OTHER: &str = "did:key:zSomeoneElse";

    fn private_owned_by(did: &str) -> GraphVisibility {
        GraphVisibility::Private {
            owner_did: did.into(),
        }
    }

    fn bearer(did: &str) -> HeaderMap {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let payload =
            URL_SAFE_NO_PAD.encode(format!(r#"{{"sub":"{did}","exp":9999999999}}"#).as_bytes());
        let mut h = HeaderMap::new();
        h.insert(
            axum::http::header::AUTHORIZATION,
            format!("Bearer eyJhbGciOiJub25lIn0.{payload}.sig")
                .parse()
                .unwrap(),
        );
        h.insert(PURPOSE_HEADER, "reading my own notes".parse().unwrap());
        h.insert("x-kotoba-client-ip", "203.0.113.9".parse().unwrap());
        h.insert("user-agent", "owner-app/1.0".parse().unwrap());
        h
    }

    fn state() -> KotobaState {
        std::env::set_var("KOTOBA_IPFS", "off");
        KotobaState::new(None).expect("state")
    }

    /// Run enforce_and_record and pull the enqueued receipt off the channel.
    fn record_one(
        state: &KotobaState,
        headers: &HeaderMap,
        visibility: &GraphVisibility,
        verified: Option<&str>,
    ) -> AccessReceipt {
        let mut rx = state.receipt_rx.lock().unwrap().take().expect("rx");
        let graph = KotobaCid::from_bytes(b"owner-only-test-graph");
        enforce_and_record(
            state, headers, None, &graph, visibility, "datom:q", verified,
        )
        .expect("record");
        let r = rx.try_recv().expect("receipt enqueued");
        *state.receipt_rx.lock().unwrap() = Some(rx);
        r
    }

    fn attrs(r: &AccessReceipt) -> Vec<String> {
        let subject = receipt_cid(r, 1);
        build_receipt_datoms(r, &subject, &KotobaCid::from_bytes(b"tx"))
            .into_iter()
            .map(|d| d.a)
            .collect()
    }

    #[test]
    fn visibility_classification() {
        let op = "did:key:zOperator";
        assert_eq!(
            receipt_visibility_for(&private_owned_by(OWNER), Some(OWNER), op),
            ReceiptVisibility::OwnerOnly
        );
        assert_eq!(
            receipt_visibility_for(&private_owned_by(OWNER), Some(OTHER), op),
            ReceiptVisibility::Operator,
            "someone else's data stays operator-visible"
        );
        assert_eq!(
            receipt_visibility_for(&private_owned_by(OWNER), None, op),
            ReceiptVisibility::Operator,
            "anonymous / unverified is never self-access"
        );
        assert_eq!(
            receipt_visibility_for(&private_owned_by(op), Some(op), op),
            ReceiptVisibility::Operator,
            "operator-owned graphs: hiding from the operator protects no one"
        );
        for v in [GraphVisibility::Public, GraphVisibility::Authenticated] {
            assert_eq!(
                receipt_visibility_for(&v, Some(OWNER), op),
                ReceiptVisibility::Operator,
                "no owner to bind to"
            );
        }
        assert_eq!(ReceiptVisibility::default(), ReceiptVisibility::Operator);
    }

    #[test]
    fn pre_r1_serialized_receipt_reads_as_operator() {
        let old = serde_json::json!({
            "graph_mb": "bOld", "accessor_did": "did:key:zOld", "operation": "datom:q",
            "purpose": null, "ts_unix": 1, "cacao_cid": null,
            "client_ip": null, "user_agent": null, "request_id": null
        });
        let r: AccessReceipt = serde_json::from_value(old).unwrap();
        assert_eq!(r.visibility, ReceiptVisibility::Operator);
        let ser = serde_json::to_value(AccessReceipt::default().into_owner_only()).unwrap();
        assert_eq!(ser["visibility"], "owner-only");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn self_access_records_owner_only_without_accessor_purpose_or_client_meta() {
        let state = state();
        let r = record_one(
            &state,
            &bearer(OWNER),
            &private_owned_by(OWNER),
            Some(OWNER),
        );
        assert_eq!(r.visibility, ReceiptVisibility::OwnerOnly);
        assert_eq!(r.operation, "datom:q");
        assert!(r.ts_unix > 1_700_000_000);
        assert!(r.accessor_did.is_none() && r.purpose.is_none() && r.cacao_cid.is_none());
        assert!(r.client_ip.is_none() && r.user_agent.is_none() && r.request_id.is_none());
        assert_eq!(
            attrs(&r),
            vec![
                "access/graph",
                "access/operation",
                "access/ts-unix",
                "access/visibility"
            ]
        );
    }

    #[test]
    fn owner_only_datoms_strip_fields_even_if_caller_forgot() {
        // Defence in depth: a fully-populated receipt flagged OwnerOnly still
        // emits only the minimal datoms.
        let r = AccessReceipt {
            graph_mb: "bG".into(),
            accessor_did: Some(OWNER.into()),
            operation: "datom:q".into(),
            purpose: Some("p".into()),
            ts_unix: 5,
            cacao_cid: Some("bC".into()),
            client_ip: Some("1.2.3.4".into()),
            user_agent: Some("ua".into()),
            request_id: Some("rid".into()),
            visibility: ReceiptVisibility::OwnerOnly,
        };
        assert_eq!(
            attrs(&r),
            vec![
                "access/graph",
                "access/operation",
                "access/ts-unix",
                "access/visibility"
            ]
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn other_access_stays_operator_visible_and_fully_attributed() {
        let state = state();
        let r = record_one(
            &state,
            &bearer(OTHER),
            &private_owned_by(OWNER),
            Some(OTHER),
        );
        assert_eq!(r.visibility, ReceiptVisibility::Operator);
        assert_eq!(r.accessor_did.as_deref(), Some(OTHER));
        assert_eq!(r.purpose.as_deref(), Some("reading my own notes"));
        let a = attrs(&r);
        assert!(a.contains(&"access/accessor-did".to_string()));
        assert!(a.contains(&"access/purpose".to_string()));
        assert!(!a.contains(&"access/visibility".to_string()));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn anonymous_access_is_operator_visible() {
        let state = state();
        let r = record_one(&state, &HeaderMap::new(), &GraphVisibility::Public, None);
        assert_eq!(r.visibility, ReceiptVisibility::Operator);
        assert!(r.accessor_did.is_none());
        // Anonymous on a Private graph (no verified accessor) is also Operator.
        let r = record_one(&state, &HeaderMap::new(), &private_owned_by(OWNER), None);
        assert_eq!(r.visibility, ReceiptVisibility::Operator);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn operator_listing_hides_owner_only_and_chain_verifies_with_mixed_receipts() {
        let state = state();
        let other = AccessReceipt {
            graph_mb: "bMixed".into(),
            accessor_did: Some(OTHER.into()),
            operation: "datom:q".into(),
            purpose: Some("support ticket".into()),
            ts_unix: 1_780_100_000,
            ..Default::default()
        };
        let own = AccessReceipt {
            graph_mb: "bMixed".into(),
            operation: "datom:q".into(),
            ts_unix: 1_780_100_001,
            ..Default::default()
        }
        .into_owner_only();
        // Batch 1: mixed; batch 2: owner-only alone.
        write_receipt_batch(&state, vec![other, own.clone()]).await;
        write_receipt_batch(&state, vec![own]).await;

        let quads = state
            .quad_store
            .quads_by_predicate_prefix(Some(&receipts_graph_cid()), "access/")
            .await;
        // The owner-only receipts ARE in the audit graph (2 of them)…
        let owner_only_count = quads
            .iter()
            .filter(|q| q.predicate == "access/visibility")
            .count();
        assert_eq!(owner_only_count, 2);
        // …but the operator listing only sees the third-party read.
        let listed = operator_visible_receipts(&quads, &AuditListQuery::default());
        assert_eq!(listed.len(), 1, "{listed:?}");
        assert_eq!(listed[0]["accessorDid"], OTHER);
        assert!(listed[0].get("visibility").is_none());

        // Commit chain still verifies over mixed receipts (the visibility datom
        // is inside the author-signed commit).
        let ipns = crate::xrpc::distributed_graph_ipns_name(&receipts_graph_cid());
        let record = state
            .ipns_registry
            .resolve(&kotoba_ipfs::IpnsName::new(ipns))
            .expect("head");
        let mut cursor = KotobaCid::from_multibase(&record.value);
        let mut depth = 0;
        while let Some(cid) = cursor.take() {
            let commit = kotoba_datomic::distributed::DistributedDatomCommit::load(
                &cid,
                &*state.block_store,
            )
            .unwrap()
            .unwrap();
            let verdict = kotoba_auth::verify_commit_author_sig(&commit);
            if state.operator_did.starts_with("did:key:") {
                assert_eq!(
                    verdict,
                    kotoba_auth::CommitSigVerdict::Valid,
                    "depth {depth}"
                );
            } else {
                assert!(!matches!(verdict, kotoba_auth::CommitSigVerdict::Invalid));
            }
            depth += 1;
            cursor = commit.prev.clone();
        }
        assert_eq!(depth, 2, "two batches → two commits");
    }
}
