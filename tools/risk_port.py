"""risk_port: the pinned KeyClerk engine's keyclerk.risk_port, configured for this deployment.

The engine lives in its own repository (https://github.com/keyclerk/keyclerk, pinned in requirements-keyclerk.txt); this file
configures it with config/keyclerk/keyclerk.yaml (rendered from the registers by tools/keyclerk_config.py) and makes
`import risk_port` the engine module, so the tools and scenario tests of this repository use one engine.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import keyclerk_config  # noqa: E402

keyclerk_config.setup()
from keyclerk import risk_port as _engine  # noqa: E402

sys.modules[__name__] = _engine
