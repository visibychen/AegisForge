"""Exact known-service credential guard; never log values or test prefixes."""

from app.core.errors import DomainError


def contains_credential(value, key: str) -> bool:
    if not key:
        return False
    if isinstance(value, str):
        return key in value
    if isinstance(value, dict):
        return any(
            contains_credential(k, key) or contains_credential(v, key) for k, v in value.items()
        )
    if isinstance(value, (list, tuple)):
        return any(contains_credential(item, key) for item in value)
    return False


def protect_snapshot(settings, name, text, parsed):
    if contains_credential(
        [name, text, parsed.content, parsed.fields, parsed.private_fields],
        settings.deepseek_api_key.get_secret_value(),
    ):
        raise DomainError(
            "INPUT_CONTAINS_SERVICE_CREDENTIAL", "输入包含当前服务凭据，请移除后再提交。", 422
        )
