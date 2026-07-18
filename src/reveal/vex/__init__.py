"""VEX decision and document generation support."""

from reveal.vex.base import VexDecisionPolicy
from reveal.vex.policy import DefaultVexDecisionPolicy

__all__ = [
    "DefaultVexDecisionPolicy",
    "VexDecisionPolicy",
]