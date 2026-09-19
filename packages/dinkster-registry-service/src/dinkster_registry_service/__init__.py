"""dinkster-registry-service: durable registry state over the pure model.

``RegistryStore`` persists principals, grants, releases, and review
lifecycles in one SQLite file; every mutation validates through the pure
``dinkster_registry`` models first and every load re-validates. The HTTP
surface composes this the way ``dinkster-server`` composes its stores.
"""

from .service import (
    DEFAULT_MAX_ARTIFACT_BYTES,
    ArtifactVault,
    Clock,
    ProbeError,
    Prober,
    ProbeResult,
    create_registry_app,
    utc_now,
)
from .store import SCHEMA_VERSION, RegistryStore, ReviewDecision, StoreError

__all__ = [
    "DEFAULT_MAX_ARTIFACT_BYTES",
    "SCHEMA_VERSION",
    "ArtifactVault",
    "Clock",
    "ProbeError",
    "ProbeResult",
    "Prober",
    "RegistryStore",
    "ReviewDecision",
    "StoreError",
    "create_registry_app",
    "utc_now",
]
