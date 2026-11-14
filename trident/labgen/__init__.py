"""Original Packet Tracer lab generation for CyberPatriot-style practice.

Two halves, deliberately separate:

``spec``     what the lab should be, and what was deliberately broken
``builder``  writing a ``.pkt`` from a spec, and verifying it in Packet Tracer

The generator writes only the student build. Answer keys are derived from the
same spec at grading time and are never placed in a generated file.
"""

from .builder import (
    GenerationResult,
    GenerationUnavailable,
    available,
    build_configs,
    generate,
    verify_in_packet_tracer,
)
from .spec import (
    DeviceRole,
    DeviceSpec,
    FaultCategory,
    FaultSpec,
    InterfaceSpec,
    LinkSpec,
    Severity,
    TopologySpec,
)

__all__ = [
    "DeviceRole",
    "DeviceSpec",
    "FaultCategory",
    "FaultSpec",
    "GenerationResult",
    "GenerationUnavailable",
    "InterfaceSpec",
    "LinkSpec",
    "Severity",
    "TopologySpec",
    "available",
    "build_configs",
    "generate",
    "verify_in_packet_tracer",
]
