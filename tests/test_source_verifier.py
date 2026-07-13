import httpx

from trustaix.source_verifier import SourceVerifier


def test_verifier_fetches_source_and_accepts_supported_claim() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, headers={"content-type": "text/html"}, text="<p>Earth orbits the Sun.</p>")

    verifier = SourceVerifier(transport=httpx.MockTransport(handler))
    findings = verifier.verify("Earth orbits the Sun. https://facts.example/earth", ["https://facts.example"])
    assert findings == []


def test_verifier_marks_unretrievable_or_unsupported_claim_for_review() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, headers={"content-type": "text/plain"}, text="Earth orbits the Sun.")

    verifier = SourceVerifier(transport=httpx.MockTransport(handler))
    findings = verifier.verify("Mars has oceans and cities. https://facts.example/mars", ["https://facts.example"])
    assert findings[0].rule_id == "CIT-005"


def test_verifier_rejects_private_citation_targets() -> None:
    verifier = SourceVerifier(transport=httpx.MockTransport(lambda request: httpx.Response(200, text="nope")))
    findings = verifier.verify("A claim with a source. http://127.0.0.1/internal")
    assert findings[0].rule_id == "CIT-004"
