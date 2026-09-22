# -*- coding: utf-8 -*-
"""tests/test_jobs.py · 任务队列"""
import time

import pytest

from app.services import JobQueue, JobState


def _wait(jq, job, timeout=5.0):
    t0 = time.time()
    while time.time() - t0 < timeout:
        if job.state in (JobState.DONE, JobState.FAILED, JobState.CANCELLED):
            return
        time.sleep(0.02)
    raise AssertionError("任务未在超时内完成")


def test_job_success():
    jq = JobQueue()
    jq.start()
    job = jq.submit(lambda: 6 * 7, name="answer")
    _wait(jq, job)
    assert job.state == JobState.DONE
    assert job.result == 42
    jq.stop()


def test_job_failure():
    jq = JobQueue()
    jq.start()

    def boom():
        raise ValueError("nope")

    job = jq.submit(boom, name="boom")
    _wait(jq, job)
    assert job.state == JobState.FAILED
    assert "ValueError" in job.error
    jq.stop()


def test_job_progress_injection():
    jq = JobQueue()
    jq.start()

    def task(progress=None, cancel=None):
        for i in range(1, 4):
            if progress:
                progress(i, 3)
        return "ok"

    job = jq.submit(task, name="prog")
    _wait(jq, job)
    assert job.state == JobState.DONE
    assert job.progress == (3, 3)
    assert job.percent == 100
    jq.stop()


def test_job_stats():
    jq = JobQueue()
    jq.start()
    jq.submit(lambda: 1, name="a")
    jq.submit(lambda: 2, name="b")
    time.sleep(0.3)
    s = jq.stats()
    assert s["total"] >= 2
    jq.stop()
