"""
Integration tests for Streamlit Frontend using AppTest.
"""

import pytest
from streamlit.testing.v1 import AppTest


def test_dashboard_app_initialization():
    at = AppTest.from_file("dashboard/app.py", default_timeout=30)
    at.run()
    assert not at.exception, f"App threw an unhandled exception: {at.exception}"


def test_dashboard_page_switching():
    at = AppTest.from_file("dashboard/app.py", default_timeout=30)
    at.run()

    # Find the radio widget for page navigation
    if at.sidebar.radio:
        radio = at.sidebar.radio[0]
        # Switch to Priority Queue
        radio.set_value("Priority Queue").run()
        assert not at.exception

        # Switch to Incident Discovery
        radio.set_value("Incident Discovery").run()
        assert not at.exception

        # Switch to Alert Investigation
        radio.set_value("Alert Investigation").run()
        assert not at.exception

        # Switch to Context & Gaps
        radio.set_value("Context & Gaps").run()
        assert not at.exception

        # Switch to Batch Prediction
        radio.set_value("Batch Prediction").run()
        assert not at.exception

        # Switch to Live Alert Prediction
        radio.set_value("Live Alert Prediction").run()
        assert not at.exception

        # Switch to CSE Regulatory Assessment
        radio.set_value("CSE Regulatory Assessment").run()
        assert not at.exception
