# SPDX-License-Identifier: ISC
"""Additional Flask routes for the live packet-derived Type-2 chart.

Registered by visualizer_server.py. Existing topology/route-chart handlers are
independent. Only the latest capture run and 300 recent samples are retained.
"""

import math
import threading
import time
from collections import deque

from flask import Blueprint, current_app, jsonify, render_template, request


class Type2ChartState:
    """Keep cumulative per-capture counters and bounded history for page refresh."""

    def __init__(self):
        self.lock = threading.Lock()
        self.history = deque(maxlen=300)
        self.state = {
            "run_id": None, "status": "waiting", "started_epoch": None,
            "updated_epoch": None, "directory": "", "errors": [],
            "current": {"by_capture_point": {}, "total": {"advertisement": 0, "withdrawal": 0}},
        }

    def accept(self, event):
        """Validate a monitor snapshot and store it; return False for older runs.

        Args: event (dict): run_id, started_epoch, status, and cumulative
            by_capture_point counts from Type2LiveMonitor. Values are NLRI
            transmissions, not route-table sizes or BGP packet counts.
        Returns: bool: True if the new snapshot was accepted.
        Raises: ValueError for malformed or decreasing counters.
        """
        if not isinstance(event, dict):
            raise ValueError("Expected a JSON object")
        run_id = event.get("run_id")
        started = event.get("started_epoch")
        status = event.get("status")
        points = event.get("by_capture_point")
        if not isinstance(run_id, str) or not run_id or len(run_id) > 200:
            raise ValueError("run_id must be a nonempty string")
        if not isinstance(started, (int, float)) or not math.isfinite(started):
            raise ValueError("started_epoch must be a finite Unix timestamp")
        if status not in ("running", "stopped", "error"):
            raise ValueError("Invalid capture status")
        if not isinstance(points, dict) or not points or len(points) > 32:
            raise ValueError("Expected 1..32 capture points")
        total = {"advertisement": 0, "withdrawal": 0}
        counts = {}
        for name, point in points.items():
            if not isinstance(name, str) or not name or len(name) > 80:
                raise ValueError("Invalid capture-point name")
            if not isinstance(point, dict):
                raise ValueError("Expected per-point counters")
            counts[name] = {}
            for kind in ("advertisement", "withdrawal"):
                value = point.get(kind)
                if type(value) is not int or value < 0:
                    raise ValueError("Counters must be nonnegative integers")
                counts[name][kind] = value
                total[kind] += value
        with self.lock:
            if self.state["run_id"] != run_id:
                previous_start = self.state["started_epoch"]
                if previous_start is not None and started < previous_start:
                    return False
                self.history.clear()
            else:
                previous = self.state["current"]["by_capture_point"]
                for name, point in previous.items():
                    if name not in counts:
                        raise ValueError("Capture points cannot disappear during a run")
                    for kind in ("advertisement", "withdrawal"):
                        if counts[name][kind] < point[kind]:
                            raise ValueError("Cumulative counters cannot decrease")
            now = time.time()
            sample = {"timestamp_epoch": now, "by_capture_point": counts, "total": total}
            self.history.append(sample)
            self.state = {
                "run_id": run_id, "status": status, "started_epoch": started,
                "updated_epoch": now, "directory": str(event.get("directory", "")),
                "errors": event.get("errors", []), "current": sample,
            }
        return True

    def snapshot(self):
        """Return the latest counters and history for refresh/reconnecting pages."""
        with self.lock:
            result = dict(self.state)
            result["history"] = list(self.history)
        return result


type2_pages = Blueprint("type2_live", __name__)


@type2_pages.route("/type2-chart")
def type2_chart():
    """Serve the separate live Type-2 advertisement/withdrawal page."""
    return render_template("type2_chart.html")


@type2_pages.route("/api/type2-counts")
def type2_counts():
    """Serve current cumulative counts plus bounded history, with no caching."""
    state = current_app.extensions["type2_chart_state"]
    response = jsonify(state.snapshot())
    response.headers["Cache-Control"] = "no-store"
    return response


@type2_pages.route("/type2-event", methods=["POST"])
def type2_event():
    """Receive a live decoder snapshot; totals are calculated by the server."""
    try:
        state = current_app.extensions["type2_chart_state"]
        accepted = state.accept(request.get_json(silent=True))
    except ValueError as error:
        return {"error": str(error)}, 400
    return {"accepted": accepted}, 200


def register_type2_chart(app):
    """Add live Type-2 endpoints to an existing Flask app; return its state.

    Args: app: The Flask object from visualizer_server.py.
    Returns: Type2ChartState: A separate cache for the latest capture run.
    """
    state = Type2ChartState()
    app.extensions["type2_chart_state"] = state
    app.register_blueprint(type2_pages)
    return state
