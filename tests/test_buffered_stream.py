from trustaix.audit import AuditRepository
from trustaix.gateway import ChatGatewayService
from trustaix.models import ChatCompletionRequest
from trustaix.service import EvaluationService


class FakeClient:
    def create_chat_completion(self, payload):
        assert payload["stream"] is False
        return {"id": "response-1", "choices": [{"message": {"content": "A safe model response."}}]}


def test_buffered_stream_releases_chunks_only_after_full_evaluation(tmp_path) -> None:
    gateway = ChatGatewayService(EvaluationService(AuditRepository(str(tmp_path / "audit.db"))), FakeClient())
    chunks = list(gateway.complete_buffered_stream(ChatCompletionRequest(model="test", messages=[{"role": "user", "content": "Hello"}], stream=True), chunk_size=160))
    assert "safe" in "".join(chunks)
    assert chunks[-1] == "data: [DONE]\n\n"
