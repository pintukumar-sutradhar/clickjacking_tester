from __future__ import annotations
import time
from typing import List, Optional
import httpx
from app.core.models import (
    FrameAncestorsResult,
    FrameAncestorsValue,
    FrameProtectionReport,
    ProtectionVerdict,
    TargetAnalysisResult,
    XFrameOptionsResult,
    XFrameOptionsValue,
)

DEFAULT_TIMEOUT_SECONDS = 12.0
DEFAULT_USER_AGENT = "ClickjackingTester/1.0 (+authorized-security-testing)"


def _parse_x_frame_options(raw_header: Optional[str]) -> XFrameOptionsResult:
    if raw_header is None:
        return XFrameOptionsResult(
            raw_value=None,
            classification=XFrameOptionsValue.MISSING,
            explanation="No X-Frame-Options header was returned. Browsers that do not honour CSP frame-ancestors will not block framing based on this header alone.",
        )
    normalized = raw_header.strip()
    upper = normalized.upper()
    if upper == "DENY":
        return XFrameOptionsResult(
            raw_value=raw_header,
            classification=XFrameOptionsValue.DENY,
            explanation="DENY instructs browsers to block framing in all contexts.",
        )
    if upper == "SAMEORIGIN":
        return XFrameOptionsResult(
            raw_value=raw_header,
            classification=XFrameOptionsValue.SAMEORIGIN,
            explanation="SAMEORIGIN instructs browsers to only allow framing by pages from the same origin as the framed page.",
        )
    if upper.startswith("ALLOW-FROM"):
        parts = normalized.split(None, 1)
        domain = parts[1].strip() if len(parts) > 1 else None
        return XFrameOptionsResult(
            raw_value=raw_header,
            classification=XFrameOptionsValue.ALLOW_FROM,
            allow_from_domain=domain,
            explanation=f"ALLOW-FROM attempts to allow framing only from '{domain}'. Note: ALLOW-FROM is obsolete and ignored by most modern browsers (Chrome, Edge, Safari), which may render this protection ineffective.",
        )
    return XFrameOptionsResult(
        raw_value=raw_header,
        classification=XFrameOptionsValue.INVALID,
        explanation=f"The value '{raw_header}' is not a recognised X-Frame-Options value (expected DENY, SAMEORIGIN or ALLOW-FROM). Browsers may ignore invalid values entirely, allowing framing.",
    )


def _extract_frame_ancestors_directive(csp_header: Optional[str]) -> Optional[str]:
    if not csp_header:
        return None
    for raw_directive in csp_header.split(";"):
        directive = raw_directive.strip()
        if directive.lower().startswith("frame-ancestors"):
            return directive
    return None


def _parse_frame_ancestors(csp_header: Optional[str]) -> FrameAncestorsResult:
    directive = _extract_frame_ancestors_directive(csp_header)
    if directive is None:
        return FrameAncestorsResult(
            raw_directive=None,
            classification=FrameAncestorsValue.MISSING,
            explanation="No frame-ancestors directive was found in the Content-Security-Policy header (or no CSP header was sent).",
        )
    tokens = directive.split(None, 1)
    sources_str = tokens[1].strip() if len(tokens) > 1 else ""
    sources: List[str] = sources_str.split() if sources_str else []
    if not sources:
        return FrameAncestorsResult(
            raw_directive=directive,
            classification=FrameAncestorsValue.INVALID,
            explanation="The frame-ancestors directive was present but specified no sources.",
        )
    normalized_sources = [s.strip("'\"") for s in sources]
    if len(normalized_sources) == 1 and normalized_sources[0].lower() == "none":
        return FrameAncestorsResult(
            raw_directive=directive,
            classification=FrameAncestorsValue.NONE,
            allowed_sources=[],
            explanation="frame-ancestors 'none' blocks framing from any origin, including the page's own origin.",
        )
    if len(normalized_sources) == 1 and normalized_sources[0].lower() == "self":
        return FrameAncestorsResult(
            raw_directive=directive,
            classification=FrameAncestorsValue.SELF,
            allowed_sources=["'self'"],
            explanation="frame-ancestors 'self' only allows framing by pages on the same origin.",
        )
    if "*" in normalized_sources:
        return FrameAncestorsResult(
            raw_directive=directive,
            classification=FrameAncestorsValue.WILDCARD,
            allowed_sources=normalized_sources,
            explanation="frame-ancestors * allows framing from ANY origin. This explicitly permits clickjacking attacks from any attacker controlled page.",
        )
    return FrameAncestorsResult(
        raw_directive=directive,
        classification=FrameAncestorsValue.ALLOWED_DOMAINS,
        allowed_sources=normalized_sources,
        explanation="frame-ancestors restricts framing to the specific listed domain(s): "
        + ", ".join(normalized_sources),
    )


def _derive_verdict(
    xfo: XFrameOptionsResult, fa: FrameAncestorsResult
) -> tuple[ProtectionVerdict, str]:
    if fa.classification in (FrameAncestorsValue.NONE, FrameAncestorsValue.SELF):
        return (
            ProtectionVerdict.PROTECTED,
            "CSP frame-ancestors blocks cross-origin framing in modern browsers, overriding X-Frame-Options where both are present.",
        )
    if fa.classification == FrameAncestorsValue.ALLOWED_DOMAINS:
        return (
            ProtectionVerdict.PARTIALLY_PROTECTED,
            "CSP frame-ancestors restricts framing to specific trusted domains only. The page is protected against framing from any other origin, including a typical attacker-hosted PoC page.",
        )
    if fa.classification == FrameAncestorsValue.WILDCARD:
        if xfo.classification in (
            XFrameOptionsValue.DENY,
            XFrameOptionsValue.SAMEORIGIN,
        ):
            return (
                ProtectionVerdict.VULNERABLE,
                "frame-ancestors * explicitly allows framing from any origin and takes precedence over X-Frame-Options in modern browsers, so the page is framable.",
            )
        return (
            ProtectionVerdict.VULNERABLE,
            "frame-ancestors * explicitly allows framing from any origin.",
        )
    if xfo.classification == XFrameOptionsValue.DENY:
        return (
            ProtectionVerdict.PROTECTED,
            "X-Frame-Options: DENY blocks framing in all contexts (no CSP frame-ancestors directive was present to override it).",
        )
    if xfo.classification == XFrameOptionsValue.SAMEORIGIN:
        return (
            ProtectionVerdict.PARTIALLY_PROTECTED,
            "X-Frame-Options: SAMEORIGIN blocks cross-origin framing, so a PoC hosted on a different origin will be blocked by compliant browsers.",
        )
    if xfo.classification == XFrameOptionsValue.ALLOW_FROM:
        return (
            ProtectionVerdict.PARTIALLY_PROTECTED,
            "X-Frame-Options: ALLOW-FROM attempts to restrict framing to one domain, but this directive is ignored by most modern browsers, so effective protection is unreliable.",
        )
    if xfo.classification == XFrameOptionsValue.INVALID:
        return (
            ProtectionVerdict.VULNERABLE,
            "The X-Frame-Options value is invalid/unrecognised and no usable CSP frame-ancestors directive is present, so browsers are likely to allow framing.",
        )
    return (
        ProtectionVerdict.VULNERABLE,
        "Neither X-Frame-Options nor CSP frame-ancestors were found. The page can be framed by any origin, making it vulnerable to clickjacking.",
    )


def analyze_headers(headers: httpx.Headers) -> FrameProtectionReport:
    xfo_raw = headers.get("x-frame-options")
    csp_raw = headers.get("content-security-policy")
    xfo_result = _parse_x_frame_options(xfo_raw)
    fa_result = _parse_frame_ancestors(csp_raw)
    verdict, explanation = _derive_verdict(xfo_result, fa_result)
    return FrameProtectionReport(
        x_frame_options=xfo_result,
        frame_ancestors=fa_result,
        verdict=verdict,
        verdict_explanation=explanation,
    )


async def analyze_target(
    url: str, timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS
) -> TargetAnalysisResult:
    start = time.perf_counter()
    try:
        async with httpx.AsyncClient(
            follow_redirects=True,
            timeout=timeout_seconds,
            headers={"User-Agent": DEFAULT_USER_AGENT},
        ) as client:
            response = await client.get(url)
        elapsed_ms = (time.perf_counter() - start) * 1000.0
        protection = analyze_headers(response.headers)
        return TargetAnalysisResult(
            requested_url=url,
            final_url=str(response.url),
            redirect_count=len(response.history),
            status_code=response.status_code,
            response_time_ms=round(elapsed_ms, 2),
            protection=protection,
        )
    except httpx.TimeoutException:
        return TargetAnalysisResult(requested_url=url, error="Request timed out.")
    except httpx.ConnectError as exc:
        return TargetAnalysisResult(
            requested_url=url, error=f"Connection failed: {exc}"
        )
    except httpx.HTTPError as exc:
        return TargetAnalysisResult(requested_url=url, error=f"HTTP error: {exc}")
    except Exception as exc:
        return TargetAnalysisResult(requested_url=url, error=f"Unexpected error: {exc}")
