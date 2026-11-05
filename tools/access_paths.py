"""access_paths: the pinned KeyClerk engine's keyclerk.access_paths, configured for this deployment.

The engine lives in its own repository (https://github.com/keyclerk/keyclerk, pinned in requirements-keyclerk.txt); this file
configures it with config/keyclerk/keyclerk.yaml (rendered from the registers by tools/keyclerk_config.py) and makes
`import access_paths` the engine module, so the tools and scenario tests of this repository use one engine. Run as a script it checks every instance.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import keyclerk_config  # noqa: E402

keyclerk_config.setup()
from keyclerk import access_paths as _engine  # noqa: E402

if __name__ == "__main__":
    ROOT = Path(__file__).resolve().parent.parent
    files = sorted(ROOT.glob("instances/*/access-paths.yaml"))
    sys.exit(max([_engine.main([str(f), "--records", str(f.with_name("grants.yaml"))]) for f in files] or [0]))
else:
    sys.modules[__name__] = _engine
