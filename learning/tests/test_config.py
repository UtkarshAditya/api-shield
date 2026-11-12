import pytest

from apishield_learning.config import ConfigurationError, LearningConfig


def test_config_uses_gateway_stream_default_and_learner_group():
    config = LearningConfig.from_env({})

    assert config.redis_url == "redis://127.0.0.1:6379/0"
    assert config.event_stream == "apishield:traffic"
    assert config.consumer_group == "learner"
    assert config.pseudo_salt == "dev-only-pseudo-salt"
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
            "APISHIELD_PSEUDO_SALT": "shared-test-salt",
        }
    )

    assert config.redis_url == "redis://redis:6379/4"
    assert config.event_stream == "custom:events"
    assert config.consumer_group == "learning-v2"
    assert config.consumer_name == "worker-1"
    assert config.batch_size == 24
    assert config.block_ms == 0
    assert config.require_pseudo_salt() == "shared-test-salt"
    assert config.internal_pseudonymization_key() == (
        LearningConfig.from_env(
            {"APISHIELD_PSEUDO_SALT": "shared-test-salt"}
        ).internal_pseudonymization_key()
    )


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


def test_config_uses_shared_salt_without_legacy_secret_setting():
    config = LearningConfig.from_env({"APISHIELD_PSEUDO_SALT": "shared-salt"})

    assert config.require_pseudo_salt() == "shared-salt"


def test_config_rejects_explicitly_empty_shared_salt():
    with pytest.raises(ConfigurationError, match="must not be empty"):
        LearningConfig(pseudo_salt="").require_pseudo_salt()


def test_internal_pseudonymization_key_is_stable_and_domain_separated():
    first = LearningConfig(pseudo_salt="same-salt").internal_pseudonymization_key()
    second = LearningConfig(pseudo_salt="same-salt").internal_pseudonymization_key()
    different = LearningConfig(pseudo_salt="other-salt").internal_pseudonymization_key()

    assert first == second
    assert first != different
