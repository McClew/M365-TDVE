# SOC training & detection-reference layer.
#
# This package turns the engine into a training aid: for each identity / M365
# attack technique it documents WHAT the attack is, WHERE it shows up in the
# audit logs, HOW to detect it, and HOW to respond. It is reference material for
# on-call SOC and support engineers - it describes attacks, it does not perform
# them.

from .reference import REFERENCE_LIBRARY, TechniqueReference, DetectionQuery
from .cards import write_all_cards, render_card, render_index
from .scenarios import SCENARIO_LIBRARY, build_timeline, render_scenario

__all__ = [
    "REFERENCE_LIBRARY",
    "TechniqueReference",
    "DetectionQuery",
    "write_all_cards",
    "render_card",
    "render_index",
    "SCENARIO_LIBRARY",
    "build_timeline",
    "render_scenario",
]
