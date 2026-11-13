"""No raw IP, raw `user_<sub>` caller, request id or payload text reaches any Admin table."""

import json

from admin_api.db import Base
from admin_api.privacy import pseudonymize
from sqlalchemy import select

from live_helpers import RAW_IP, RAW_USER, SALT, attack, make_learner, make_storage, warm_up


def dump_all_tables(storage) -> str:
    out = []
    with storage.session_factory() as session:
        for table in Base.metadata.sorted_tables:
            for row in session.execute(select(table)):
                out.append(json.dumps([str(v) for v in row], default=str))
    return "\n".join(out)


def test_nothing_raw_is_persisted(tmp_path):
    storage = make_storage(tmp_path, flush_interval=0)
    learner = make_learner(storage)
    warm_up(learner)
    alerts = attack(learner, 41, caller=RAW_USER, ip=RAW_IP)
    alerts += attack(learner, 60, caller="203.0.113.99", ip="203.0.113.99")  # bare-IP caller
    learner.write_state()
    learner.close()
    assert alerts, "the attack should produce alerts"

    text = dump_all_tables(storage)
    assert "alerts" in {t.name for t in Base.metadata.sorted_tables}
    for raw in (RAW_IP, "203.0.113.99", RAW_USER, "alice-sub-1234", "req-41", "shape-search-sqli", "sqli\""):
        assert raw not in text, raw
    assert pseudonymize(RAW_USER, SALT) in text  # the shared pseudonym is what is stored
    assert pseudonymize("203.0.113.99", SALT) in text
