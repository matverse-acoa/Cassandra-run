"""Ferramentas de revisão sistêmica para o MatVerse."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Iterable, Tuple

import numpy as np

Array = np.ndarray
ConstraintFn = Callable[[Array], Iterable[float]]


@dataclass
class ReviewResult:
    """Resultado do protocolo de revisão sistêmica."""

    functional_value: float
    lambda_min: float
    approved: bool


def constraint_jac(x: Array, funcs: ConstraintFn, eps: float = 1e-8) -> Array:
    """Calcula a Jacobiana das restrições via diferenças centrais."""
    x = np.asarray(x, dtype=float)
    base = np.asarray(list(funcs(x)), dtype=float)
    m = base.size
    n = x.size
    jacobian = np.zeros((m, n), dtype=float)

    for j in range(n):
        dx = np.zeros_like(x)
        dx[j] = eps
        f_plus = np.asarray(list(funcs(x + dx)), dtype=float)
        f_minus = np.asarray(list(funcs(x - dx)), dtype=float)
        jacobian[:, j] = (f_plus - f_minus) / (2.0 * eps)

    return jacobian


def failure_tensor(x: Array, funcs: ConstraintFn, eps: float = 1e-6, gamma: float = 1.0) -> Array:
    """Calcula o tensor de falha generalizada Φ usando aproximações numéricas."""
    x = np.asarray(x, dtype=float)
    base_jac = constraint_jac(x, funcs, eps=eps)
    m, n = base_jac.shape
    hessian = np.zeros((n, n), dtype=float)
    weights = np.ones(m, dtype=float)

    for i in range(n):
        dx = np.zeros_like(x)
        dx[i] = eps
        jac_plus = constraint_jac(x + dx, funcs, eps=eps)
        jac_minus = constraint_jac(x - dx, funcs, eps=eps)
        grad_plus = jac_plus.T @ weights
        grad_minus = jac_minus.T @ weights
        hessian[i, :] = (grad_plus - grad_minus) / (2.0 * eps)

    hessian = 0.5 * (hessian + hessian.T)
    return hessian + gamma * np.eye(n)


def review_functional(
    phi: Array,
    area: float,
    alpha: float = 1.0,
    beta: float = 0.5,
    gamma: float = 0.2,
) -> float:
    """Avalia o funcional de revisão ℛ[Φ]."""
    if area <= 0:
        raise ValueError("A área deve ser positiva para avaliação do funcional.")

    norm_phi = np.linalg.norm(phi, ord="fro") ** 2
    gradients = np.gradient(phi)
    grad_phi = sum(np.linalg.norm(grad, ord="fro") ** 2 for grad in gradients)
    ricci = abs(np.trace(phi))

    return area * (alpha * norm_phi + beta * grad_phi + gamma * ricci)


def system_review(
    x: Array,
    funcs: ConstraintFn,
    area: float,
    lambda_threshold: float = 1e-3,
) -> ReviewResult:
    """Executa o protocolo completo de revisão sistêmica."""
    phi = failure_tensor(x, funcs)
    functional_value = review_functional(phi, area)
    eigenvalues = np.linalg.eigvals(phi)
    lambda_min = float(np.min(eigenvalues.real))
    approved = lambda_min > lambda_threshold

    return ReviewResult(
        functional_value=functional_value,
        lambda_min=lambda_min,
        approved=approved,
    )


def _example() -> Tuple[ReviewResult, Array]:
    """Executa um exemplo padrão com variedade 7-D."""
    x = np.random.randn(7)

    def constraints(vector: Array) -> Iterable[float]:
        return [vector[0] ** 2 + vector[1] ** 2 + vector[2] ** 2 - 1.0]

    area = 4.0 * np.pi
    result = system_review(x, constraints, area)
    return result, x


def main() -> None:
    """Executa o módulo de revisão com exemplo determinístico."""
    np.random.seed(7)
    result, vector = _example()

    print("Vetor de estado:", vector)
    print("Revisão funcional ℛ[Φ] =", result.functional_value)
    print("Autovalor mínimo λ_min(Φ) =", result.lambda_min)
    print("Status:", "✅ Aprovado" if result.approved else "❌ Reprovado")


if __name__ == "__main__":
    main()
