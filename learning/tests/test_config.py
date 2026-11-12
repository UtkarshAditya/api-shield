import pytest

from apishield_learning.config import ConfigurationError, LearningConfig


def test_config_uses_gateway_stream_default_and_dedicated_m3_group():
    config = LearningConfig.from_env({})

    assert config.redis_url == "redis://127.0.0.1:6379/0"
    assert config.event_stream == "apishield:traffic"
    assert config.consumer_group == "apishield-m3"
    assert config.batch_size == 100


def test_config_reads_stream_and_consumer_settings_from_environment():
    config = LearningConfig.from_env(
        {
            "APISHIELD_REDIS_URL": "redis://redis:6379/4",
            "APISHIELD_EVENT_STREAM": "custom:events",
            "APISHIELD_LEARNING_CONSUMER_GROUP": "learning-v2",
            "APISHIELD_LEARNING_CONSUMER_NAME": "worker-1",
            "APISHIELD_LEARNING_BATCH_SIZE": "24",
            "APISHIELD_LEARNING_BLOCK_MS": "0",
            "APISHIELD_PSEUDONYMIZATION_KEY": "0123456789abcdef",
        }
    )

    assert config.redis_url == "redis://redis:6379/4"
    assert config.event_stream == "custom:events"
    assert config.consumer_group == "learning-v2"
    assert config.consumer_name == "worker-1"
    assert config.batch_size == 24
    assert config.block_ms == 0
    assert config.require_pseudonymization_key() == b"0123456789abcdef"


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("APISHIELD_LEARNING_BATCH_SIZE", "zero"),
        ("APISHIELD_LEARNING_BATCH_SIZE", "0"),
        ("APISHIELD_LEARNING_BLOCK_MS", "-1"),
    ],
)
def test_config_rejects_invalid_integer_settings(name, value):
    with pytest.raises(ConfigurationError):
        LearningConfig.from_env({name: value})


def test_config_requires_strong_key_only_when_pseudonymization_is_requested():
    with pytest.raises(ConfigurationError, match="required"):
        LearningConfig.from_env({}).require_pseudonymization_key()
    with pytest.raises(ConfigurationError, match="at least 16"):
        LearningConfig.from_env(
            {"APISHIELD_PSEUDONYMIZATION_KEY": "too-short"}
        ).require_pseudonymization_key()
