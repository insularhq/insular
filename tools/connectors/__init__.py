"""connectors: the pinned KeyClerk engine's keyclerk.connectors, configured for this deployment."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import keyclerk_config  # noqa: E402

keyclerk_config.setup()
import keyclerk.connectors  # noqa: E402
import keyclerk.connectors.contract  # noqa: E402,F401
import keyclerk.connectors.keycloak  # noqa: E402,F401
import keyclerk.connectors.sources  # noqa: E402,F401
import keyclerk.connectors.physical  # noqa: E402,F401

for _name in ['contract', 'keycloak', 'sources', 'physical']:
    sys.modules[f"connectors.{_name}"] = getattr(keyclerk.connectors, _name)
sys.modules[__name__] = keyclerk.connectors
