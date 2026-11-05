"""piam: the pinned KeyClerk engine's keyclerk.piam, configured for this deployment."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import keyclerk_config  # noqa: E402

keyclerk_config.setup()
import keyclerk.piam  # noqa: E402
import keyclerk.piam.core  # noqa: E402,F401
import keyclerk.piam.pacs  # noqa: E402,F401
import keyclerk.piam.osdp_controller  # noqa: E402,F401

for _name in ['core', 'pacs', 'osdp_controller']:
    sys.modules[f"piam.{_name}"] = getattr(keyclerk.piam, _name)
sys.modules[__name__] = keyclerk.piam
