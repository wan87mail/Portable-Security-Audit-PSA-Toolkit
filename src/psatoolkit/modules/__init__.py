"""Assessment module registry.

To add a module: create ``modules/<name>.py`` with a ``build_module()``
function returning a :class:`psatoolkit.core.engine.Module`, then append it
to :data:`MODULE_BUILDERS`.
"""

from __future__ import annotations

from psatoolkit.core.engine import Module
from psatoolkit.modules import demo, system_info

MODULE_BUILDERS = [
    system_info.build_module,
    demo.build_module,
]


def load_modules() -> list[Module]:
    return [build() for build in MODULE_BUILDERS]
