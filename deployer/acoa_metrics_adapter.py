from __future__ import annotations

from typing import Any, Dict

from acoa.metrics.coherence import CoherenceIndex
from acoa.metrics.cvar import CVaREstimator

_PSI = CoherenceIndex(d_max=10.0)
_CVAR = CVaREstimator(alpha=0.95, window=256)


def compute_acoa_metrics(payload: Dict[str, Any]) -> Dict[str, float]:
    """
    Calcula métricas ACOA reais (Ψ, CVaR) a partir do payload.
    Fail-closed: qualquer exceção deve abortar a operação.
    """
    psi_value = float(_PSI(payload))
    loss = max(0.0, 1.0 - psi_value)
    cvar_estimate = _CVAR.update(loss).cvar

    return {
        "psi": psi_value,
        "cvar95": float(cvar_estimate),
    }
