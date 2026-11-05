"""records: the pinned KeyClerk engine's keyclerk.records, configured for this deployment.

The engine lives in its own repository (https://github.com/keyclerk/keyclerk, pinned in requirements-keyclerk.txt); this file
configures it with config/keyclerk/keyclerk.yaml (rendered from the registers by tools/keyclerk_config.py) and makes
`import records` the engine module, so the tools and scenario tests of this repository use one engine.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import keyclerk_config  # noqa: E402

keyclerk_config.setup()
from keyclerk import records as _engine  # noqa: E402

sys.modules[__name__] = _engine
