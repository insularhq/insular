"""situation: the pinned KeyClerk engine's keyclerk.situation, configured for this deployment.

The engine lives in its own repository (https://github.com/keyclerk/keyclerk, pinned in requirements-keyclerk.txt); this file
configures it with config/keyclerk/keyclerk.yaml (rendered from the registers by tools/keyclerk_config.py) and makes
`import situation` the engine module, so the tools and scenario tests of this repository use one engine. Run as a script it checks every instance.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import keyclerk_config  # noqa: E402

keyclerk_config.setup()
from keyclerk import situation as _engine  # noqa: E402

if __name__ == "__main__":
    ROOT = Path(__file__).resolve().parent.parent
    sys.exit(_engine.main(sys.argv[1:] or [str(f) for f in sorted(ROOT.glob('instances/*/grants.yaml')) if 'situations:' in f.read_text(encoding='utf-8') or 'surge_packages:' in f.read_text(encoding='utf-8')]))
else:
    sys.modules[__name__] = _engine
