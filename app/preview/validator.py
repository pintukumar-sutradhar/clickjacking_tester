from __future__ import annotations
from app.core.models import (
    FrameProtectionReport,
    ProtectionVerdict,
    TargetAnalysisResult,
    ValidationOutcome,
    ValidationResult,
)


def validate_poc(analysis: TargetAnalysisResult) -> ValidationResult:
    if analysis.error:
        return ValidationResult(
            outcome=ValidationOutcome.NETWORK_ERROR,
            explanation=f"The target could not be reached during analysis: {analysis.error}. The iframe in the generated PoC is likely to fail to load for the same reason.",
        )
    protection: FrameProtectionReport | None = analysis.protection
    if protection is None:
        return ValidationResult(
            outcome=ValidationOutcome.UNKNOWN,
            explanation="No frame protection data is available for this target yet. Run analysis first.",
        )
    if protection.verdict == ProtectionVerdict.VULNERABLE:
        return ValidationResult(
            outcome=ValidationOutcome.LOADED,
            explanation=f"Neither X-Frame-Options nor CSP frame-ancestors block framing from this PoC's origin, so the target content is expected to load successfully inside the iframe: {protection.verdict_explanation}",
        )
    if protection.frame_ancestors.classification.value == "allowed_domains":
        return ValidationResult(
            outcome=ValidationOutcome.BLOCKED_CSP_FRAME_ANCESTORS,
            explanation=f"CSP frame-ancestors restricts framing to specific trusted domains, and the local PoC server's origin is not in that list, so the browser is expected to block the frame: {protection.verdict_explanation}",
        )
    if protection.frame_ancestors.classification.value in ("none", "self"):
        return ValidationResult(
            outcome=ValidationOutcome.BLOCKED_CSP_FRAME_ANCESTORS,
            explanation=f"CSP frame-ancestors is expected to block this frame in modern, standards-compliant browsers: {protection.verdict_explanation}",
        )
    if protection.x_frame_options.classification.value in ("deny", "sameorigin"):
        return ValidationResult(
            outcome=ValidationOutcome.BLOCKED_X_FRAME_OPTIONS,
            explanation=f"X-Frame-Options is expected to block this frame: {protection.verdict_explanation}",
        )
    return ValidationResult(
        outcome=ValidationOutcome.UNKNOWN,
        explanation="The frame protection signals were inconclusive. Load the PoC in an actual browser and inspect the developer console for a definitive result: "
        + protection.verdict_explanation,
    )
