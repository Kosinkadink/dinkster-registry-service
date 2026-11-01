from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import UUID7, BaseModel, ConfigDict, Field, JsonValue
from pydantic.alias_generators import to_camel


class ResponseModel(BaseModel):
    model_config = ConfigDict(alias_generator=to_camel, populate_by_name=True, extra="ignore")


class Owner(ResponseModel):
    type: Literal["user", "org"]
    id: UUID7
    slug: str
    display_name: str


class TrustSummary(ResponseModel):
    scan_status: Literal["passed", "warning", "pending", "stale", "failed"]
    provenance: Literal["github_actions_oidc", "api_key", "interactive"]
    verified_attestation: bool
    warning_count: int


class PackNotice(ResponseModel):
    kind: Literal["deprecated", "ownership_transferred", "maintenance_repointed", "security"]
    message: str
    recommended_pack: str | None
    source_repository: str | None


class PackSummary(ResponseModel):
    pack_id: UUID7
    name: str
    display_name: str
    description: str
    owner: Owner
    visibility: Literal["public", "org_private"]
    latest_version: str
    latest_published_at: datetime
    node_types: list[str]
    tags: list[str]
    download_count: int
    trust_summary: TrustSummary
    pack_notice: PackNotice | None


class PackPage(ResponseModel):
    items: list[PackSummary]
    next_cursor: str | None


class PackDetail(ResponseModel):
    pack_id: UUID7
    name: str
    display_name: str
    description: str
    long_description: str
    owner: Owner
    visibility: Literal["public", "org_private"]
    homepage: str | None
    repository: str | None
    support: str | None
    tags: list[str]
    latest_version: str
    created_at: datetime
    updated_at: datetime
    pack_notice: PackNotice | None


class ReleaseSummary(ResponseModel):
    version: str
    state: Literal[
        "pending_scan",
        "pending_review",
        "active",
        "yanked",
        "quarantined",
        "blocked",
        "rejected",
    ]
    state_reason: str | None
    published_at: datetime
    artifact_digest: str
    artifact_size: int
    dinkster: str
    license: str
    platforms: list[str]
    node_types: list[str]
    trust_summary: TrustSummary


class ReleasePage(ResponseModel):
    items: list[ReleaseSummary]
    next_cursor: str | None


class Publisher(ResponseModel):
    kind: Literal["github_actions_oidc", "api_key", "interactive"]
    principal_id: str


class ArtifactMetadata(ResponseModel):
    digest: str
    size: int
    media_type: str
    manifest_digest: str


class Contracts(ResponseModel):
    host: str | None
    api: str | None
    inference: str | None


class Sandbox(ResponseModel):
    gpu: bool
    network: bool
    writable_mounts: bool


class ReleaseDependency(ResponseModel):
    pack_name: str
    version_range: str


class ReleaseManifest(ResponseModel):
    dinkster: str
    license: str
    contracts: Contracts
    platforms: list[str]
    sandbox: Sandbox
    python_requirements: list[str]
    dependencies: list[ReleaseDependency]
    node_source: Literal["remote-gateway-catalog"] | None = None


class ReleaseNode(ResponseModel):
    node_type: str
    schema_version: int
    schema_wire_version: int
    schema_signature: str
    role: Literal["executing", "schema-only"]


class DoctorSignal(ResponseModel):
    status: Literal["passed", "warning", "failed"]
    doctor_version: str
    report_version: int
    error_count: int
    warning_count: int


class ScanSignal(ResponseModel):
    status: Literal["passed", "warning", "pending", "stale", "failed"]
    policy_version: str
    scanned_at: datetime | None


class ProvenanceSignal(ResponseModel):
    kind: Literal["github_actions_oidc", "api_key", "interactive"]
    verified: bool
    repository: str | None
    commit_sha: str | None
    workflow_ref: str | None


class AttestationSignal(ResponseModel):
    status: Literal["verified", "missing", "invalid"]
    statement_url: str | None


class VulnerabilitySignal(ResponseModel):
    status: Literal["current", "stale", "unavailable"]
    critical: int
    high: int
    moderate: int
    low: int
    database_as_of: datetime | None


class Finding(ResponseModel):
    code: str
    severity: Literal["info", "warning", "error", "critical"]
    message: str


class TrustSignals(ResponseModel):
    doctor: DoctorSignal
    scan: ScanSignal
    provenance: ProvenanceSignal
    attestation: AttestationSignal
    vulnerabilities: VulnerabilitySignal
    findings: list[Finding]


class CloudEligibility(ResponseModel):
    registry_eligible: bool
    reason_codes: list[str]
    policy_version: str


class InstallationLock(ResponseModel):
    base_id: str
    artifact_digest: str
    digest: str
    size: int
    url: str


class ReleaseDetail(ResponseModel):
    pack_id: UUID7
    pack_name: str
    version: str
    state: Literal[
        "pending_scan",
        "pending_review",
        "active",
        "yanked",
        "quarantined",
        "blocked",
        "rejected",
    ]
    state_reason: str | None
    state_changed_at: datetime
    published_at: datetime
    published_by: Publisher
    artifact: ArtifactMetadata
    install_locks: dict[str, InstallationLock] = Field(default_factory=dict)
    manifest: ReleaseManifest
    nodes: list[ReleaseNode]
    trust_signals: TrustSignals
    cloud: CloudEligibility


class SchemaEntry(ReleaseNode):
    schema_document: dict[str, JsonValue] = Field(alias="schema", serialization_alias="schema")


class SchemasResponse(ResponseModel):
    pack_name: str
    version: str
    schemas: list[SchemaEntry]


class NodeProvider(ResponseModel):
    pack_id: UUID7
    pack_name: str
    display_name: str
    owner: Owner
    visibility: Literal["public", "org_private"]
    version: str
    schema_version: int
    schema_signature: str
    role: Literal["executing", "schema-only"]
    artifact_digest: str
    trust_summary: TrustSummary


class NodeProvidersResponse(ResponseModel):
    node_type: str
    providers: list[NodeProvider]


class DownloadTicket(ResponseModel):
    pack_name: str
    version: str
    state: Literal["active", "yanked"]
    warning: str | None
    artifact_digest: str
    artifact_size: int
    url: str
    expires_at: datetime | None
    required_headers: dict[str, str]


class SecurityBlock(ResponseModel):
    pack_name: str
    version: str
    artifact_digest: str
    blocked_at: datetime
    reason_code: str
    message: str
    fixed_version: str | None


class SecurityBlocksResponse(ResponseModel):
    generated_at: datetime
    items: list[SecurityBlock]
    next_cursor: str | None


ErrorCode = Literal[
    "invalid_request",
    "unauthenticated",
    "forbidden",
    "not_found",
    "name_unavailable",
    "version_conflict",
    "publish_in_progress",
    "quota_exceeded",
    "artifact_too_large",
    "admission_rejected",
    "release_yanked",
    "release_quarantined",
    "release_blocked",
    "release_legally_blocked",
    "rate_limited",
    "scan_unavailable",
    "internal",
]


class ErrorDetail(ResponseModel):
    code: ErrorCode
    message: str
    retryable: bool
    request_id: UUID7
    detail: dict[str, JsonValue] | None


class ErrorResponse(ResponseModel):
    error: ErrorDetail


class HealthResponse(ResponseModel):
    status: Literal["ok"]
    packs: int
    releases: int
    artifacts: int
