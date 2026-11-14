"""
Pytest configuration and test isolation fixtures for SAT-SA.
Ensures zero pollution of production submission directories during automated test execution.
"""

import pytest
from pathlib import Path

@pytest.fixture(scope="session", autouse=True)
def isolate_test_submissions(tmp_path_factory):
    """
    Ensure all batch predictions, manifests, and live prediction history
    created during test runs are written to an isolated temporary test directory,
    preventing any test pollution in production data/submissions/.
    """
    session_tmp = tmp_path_factory.mktemp("submissions")
    test_manifest = session_tmp / "submission_manifest.json"
    test_live_hist = session_tmp / "live_prediction_history.json"

    import backend.batch_prediction as bp
    import backend.live_prediction as lp

    bp.SUBMISSIONS_DIR = session_tmp
    bp.MANIFEST_FILE = test_manifest
    lp.LIVE_HISTORY_FILE = test_live_hist
    yield
