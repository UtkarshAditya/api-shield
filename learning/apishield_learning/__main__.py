"""Run a development consumer that writes safe feature records to stdout."""

from __future__ import annotations

import asyncio
import json
import logging
import sys

from .config import LearningConfig
from .consumer import FeatureEnvelope, RedisStreamConsumer


async def _run() -> None:
    config = LearningConfig.from_env()
    consumer = RedisStreamConsumer.from_config(config)

    async def write_to_stdout(envelope: FeatureEnvelope) -> None:
        line = json.dumps(envelope.features.to_dict(), separators=(",", ":"))
        sys.stdout.write(line + "\n")
        sys.stdout.flush()

    await consumer.run(write_to_stdout)


def main() -> None:
    logging.basicConfig(level=logging.INFO)
    try:
        asyncio.run(_run())
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
