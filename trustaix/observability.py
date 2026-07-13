"""Small dependency-free metrics registry for Prometheus scraping."""

from collections import Counter
from threading import Lock


class MetricsRegistry:
    def __init__(self) -> None:
        self._lock = Lock()
        self._requests: Counter[tuple[str, str, int]] = Counter()
        self._evaluations: Counter[str] = Counter()

    def record_request(self, method: str, path: str, status_code: int) -> None:
        with self._lock:
            self._requests[(method, path, status_code)] += 1

    def record_evaluation(self, action: str) -> None:
        with self._lock:
            self._evaluations[action] += 1

    def render_prometheus(self) -> str:
        with self._lock:
            requests = list(self._requests.items())
            evaluations = list(self._evaluations.items())
        lines = [
            "# HELP trustaix_http_requests_total HTTP requests processed by TrustAIX.",
            "# TYPE trustaix_http_requests_total counter",
        ]
        lines.extend(
            f'trustaix_http_requests_total{{method="{method}",path="{path}",status="{status}"}} {count}'
            for (method, path, status), count in requests
        )
        lines.extend(
            [
                "# HELP trustaix_evaluations_total Risk evaluations by final action.",
                "# TYPE trustaix_evaluations_total counter",
            ]
        )
        lines.extend(
            f'trustaix_evaluations_total{{action="{action}"}} {count}'
            for action, count in evaluations
        )
        return "\n".join(lines) + "\n"
