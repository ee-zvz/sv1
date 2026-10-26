"""SV1 - page identity. Two fetches decide whether the page can be trusted.

The old scan assumed "same URL == same bytes". Real sites rotate nonces,
timestamps, ad slots and CSRF tokens on every request, which turns a stable
comparison into noise and a noise into a false positive. This module measures
that noise with the server itself before any payload is sent.
"""

from __future__ import annotations

import difflib

from . import config


def normalize(text: str) -> list[str]:
    """Whitespace tokens, capped. Truncation keeps difflib linear-ish."""
    collapsed = " ".join(text.split())
    if not collapsed:
        return []
    return collapsed.split(" ")[: config.TOKEN_LIMIT]


def similarity(left: list[str], right: list[str]) -> float:
    """Token-level sequence ratio in [0, 1]."""
    if not left and not right:
        return 1.0
    if not left or not right:
        return 0.0
    longest = max(len(left), len(right))
    if abs(len(left) - len(right)) / longest > 0.6:
        return 0.0
    matcher = difflib.SequenceMatcher(None, left, right, autojunk=False)
    return matcher.ratio()


def same_text(left: str, right: str, threshold: float | None = None) -> bool:
    return similarity(normalize(left), normalize(right)) >= (
        config.PAGE_SAME if threshold is None else threshold
    )


def text_similarity(left: str, right: str) -> float:
    return similarity(normalize(left), normalize(right))


class Baseline:
    """Reality check for one injection point."""

    def __init__(self, samples: list, point_value: str) -> None:
        self.value = point_value
        self.status = samples[0].status
        self.text = samples[0].text
        self.tokens = [normalize(sample.text) for sample in samples]
        self.elapsed = sorted(sample.elapsed for sample in samples)[len(samples) // 2]
        self.stable = all(
            similarity(self.tokens[0], other) >= config.PAGE_STABLE
            for other in self.tokens[1:]
        )

    def matches(self, text: str, threshold: float | None = None) -> bool:
        return (
            similarity(self.tokens[0], normalize(text))
            >= (config.PAGE_SAME if threshold is None else threshold)
        )

    def similarity(self, text: str) -> float:
        return similarity(self.tokens[0], normalize(text))

    def noise(self) -> float:
        """0.0 = byte-identical across fetches, 1.0 = unrelated pages."""
        if len(self.tokens) < 2:
            return 0.0
        return 1.0 - min(
            similarity(self.tokens[0], other) for other in self.tokens[1:]
        )


def capture(client, point, value: str) -> Baseline | None:
    """Fetch the untouched endpoint twice. None when the target is unreachable."""
    samples = []
    for _ in range(config.BASELINE_SAMPLES):
        response = client.send(point, value)
        if not response.ok:
            return None
        samples.append(response)
    return Baseline(samples, value)
