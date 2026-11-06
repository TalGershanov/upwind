"""Turning indicator results into a single verdict."""

from logic import config


def risk_score(results: dict, weights: dict) -> tuple:
    """Combine ``{indicator name: IndicatorResult}`` into ``(verdict, score)``.

    The weighted average of the indicator scores (``weights`` maps an
    indicator name to its weight), mapped to a verdict by
    ``config.VERDICT_THRESHOLDS``.
    """
    total = sum(weights[name] for name in results)
    if not total:
        return config.NOT_PHISHING, float(config.NOT_PHISHING)
    score = min(sum(weights[name] * result.score
                    for name, result in results.items()) / total,
                float(config.PHISHING))
    for upper, verdict in config.VERDICT_THRESHOLDS:
        if score < upper:
            return verdict, round(score, 2)
    return config.PHISHING, round(score, 2)
