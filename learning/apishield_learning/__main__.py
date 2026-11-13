"""Run the learner.

    python -m apishield_learning            # live: baselines + detectors -> alerts in the Admin DB (live.py)
    python -m apishield_learning --stdout   # development consumer: safe feature records to stdout
"""

from __future__ import annotations

import argparse
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


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="APIShield learner (M3)")
    parser.add_argument("--stdout", action="store_true",
                        help="only print safe feature records (the earlier development mode)")
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    try:
        if args.stdout:
            asyncio.run(_run())
        else:
            from .live import run_live

            asyncio.run(run_live())
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
