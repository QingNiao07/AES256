# -*- coding: utf-8 -*-
"""
app/services/jobs.py
====================
统一任务队列：进度 / 取消 / 结果 / 错误。

原版 Tk 用 ui_queue、Qt 各写一套线程逻辑，取消行为不一致。
这里把「后台执行 + 进度回调 + 可取消」抽成一份，UI 只做适配：
- Tkinter：轮询 events()
- PySide6：把 on_event 接到 Signal
"""
from __future__ import annotations

import threading
import time
import traceback
import uuid
from dataclasses import dataclass, field
from enum import Enum
from queue import Empty, Queue
from typing import Any, Callable, Optional


class JobState(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    DONE = "done"
    FAILED = "failed"
    CANCELLED = "cancelled"


@dataclass
class Event:
    job_id: str
    kind: str                  # progress | log | done | failed | cancelled
    payload: Any = None
    ts: float = field(default_factory=time.time)


@dataclass
class Job:
    fn: Callable[..., Any]
    args: tuple = ()
    kwargs: dict = field(default_factory=dict)
    name: str = "job"
    id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    state: JobState = JobState.PENDING
    progress: tuple[int, int] = (0, 0)
    result: Any = None
    error: str = ""
    created: float = field(default_factory=time.time)
    started: float = 0.0
    finished: float = 0.0

    @property
    def elapsed(self) -> float:
        if not self.started:
            return 0.0
        return (self.finished or time.time()) - self.started

    @property
    def percent(self) -> int:
        done, total = self.progress
        if total <= 0:
            return 0
        return min(100, int(done * 100 / total))


class JobCancelled(RuntimeError):
    pass


class JobQueue:
    """串行执行的后台任务队列。select 语义由 UI 侧轮询 events() 实现。"""

    def __init__(self, on_event: Optional[Callable[[Event], None]] = None):
        self._events: Queue[Event] = Queue()
        self._jobs: dict[str, Job] = {}
        self._cancel: set[str] = set()
        self._lock = threading.RLock()
        self._queue: Queue[Job] = Queue()
        self._worker: threading.Thread | None = None
        self._stop = threading.Event()
        self._external = on_event

    # ---------- 生命周期 ----------
    def start(self) -> None:
        if self._worker and self._worker.is_alive():
            return
        self._stop.clear()
        self._worker = threading.Thread(target=self._loop, name="jobqueue", daemon=True)
        self._worker.start()

    def stop(self, timeout: float = 2.0) -> None:
        self._stop.set()
        if self._worker:
            self._worker.join(timeout=timeout)

    def _emit(self, ev: Event) -> None:
        self._events.put(ev)
        if self._external:
            try:
                self._external(ev)
            except Exception:
                pass

    def events(self, max_items: int = 200) -> list[Event]:
        out = []
        for _ in range(max_items):
            try:
                out.append(self._events.get_nowait())
            except Empty:
                break
        return out

    # ---------- 提交 / 取消 ----------
    def submit(self, fn: Callable[..., Any], *args, name: str = "job", **kwargs) -> Job:
        job = Job(fn=fn, args=args, kwargs=kwargs, name=name)
        with self._lock:
            self._jobs[job.id] = job
        self._queue.put(job)
        self.start()
        self._emit(Event(job.id, "log", f"已入队：{name}"))
        return job

    def cancel(self, job_id: str) -> None:
        with self._lock:
            self._cancel.add(job_id)
        self._emit(Event(job_id, "log", "已请求取消"))

    def is_cancelled(self, job_id: str) -> bool:
        with self._lock:
            return job_id in self._cancel

    def cancel_all(self) -> None:
        with self._lock:
            for jid in self._jobs:
                self._cancel.add(jid)

    # ---------- 查询 ----------
    def get(self, job_id: str) -> Job | None:
        return self._jobs.get(job_id)

    def all_jobs(self) -> list[Job]:
        with self._lock:
            return sorted(self._jobs.values(), key=lambda j: j.created, reverse=True)

    def active(self) -> list[Job]:
        return [j for j in self.all_jobs()
                if j.state in (JobState.PENDING, JobState.RUNNING)]

    def stats(self) -> dict:
        jobs = self.all_jobs()
        return {
            "total": len(jobs),
            "active": len([j for j in jobs if j.state in (JobState.PENDING, JobState.RUNNING)]),
            "done": len([j for j in jobs if j.state == JobState.DONE]),
            "failed": len([j for j in jobs if j.state == JobState.FAILED]),
            "cancelled": len([j for j in jobs if j.state == JobState.CANCELLED]),
        }

    def clear_finished(self) -> None:
        with self._lock:
            for jid in [j.id for j in self._jobs.values()
                        if j.state in (JobState.DONE, JobState.FAILED, JobState.CANCELLED)]:
                self._jobs.pop(jid, None)

    # ---------- 内部 ----------
    def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                job = self._queue.get(timeout=0.2)
            except Empty:
                continue
            self._run(job)

    def _run(self, job: Job) -> None:
        with self._lock:
            if job.id in self._cancel:
                job.state = JobState.CANCELLED
                job.finished = time.time()
                self._emit(Event(job.id, "cancelled"))
                return
            job.state = JobState.RUNNING
            job.started = time.time()
        self._emit(Event(job.id, "log", f"开始：{job.name}"))

        def on_progress(done: int, total: int) -> None:
            job.progress = (int(done), int(total))
            self._emit(Event(job.id, "progress", job.progress))

        def should_cancel() -> bool:
            return self.is_cancelled(job.id)

        kwargs = dict(job.kwargs)
        # 仅当被调函数声明了对应形参时才注入，避免签名不匹配
        import inspect

        try:
            sig = inspect.signature(job.fn)
            params = sig.parameters
        except (TypeError, ValueError):
            params = {}
        if "progress" in params or any(p.kind == p.VAR_KEYWORD for p in params.values()):
            kwargs.setdefault("progress", on_progress)
        if "cancel" in params or any(p.kind == p.VAR_KEYWORD for p in params.values()):
            kwargs.setdefault("cancel", should_cancel)

        try:
            result = job.fn(*job.args, **kwargs)
        except JobCancelled:
            job.state = JobState.CANCELLED
            job.finished = time.time()
            self._emit(Event(job.id, "cancelled"))
        except Exception as exc:
            job.state = JobState.FAILED
            job.error = f"{type(exc).__name__}: {exc}"
            job.finished = time.time()
            self._emit(Event(job.id, "failed", {"error": job.error,
                                                "trace": traceback.format_exc()}))
        else:
            if self.is_cancelled(job.id):
                job.state = JobState.CANCELLED
                self._emit(Event(job.id, "cancelled"))
            else:
                job.state = JobState.DONE
                job.result = result
                self._emit(Event(job.id, "done", result))
            job.finished = time.time()

    # ---------- 便捷封装 ----------
    def encrypt_file(self, src, dst, master, **kw) -> Job:
        from ..core import container

        def _task(progress=None, cancel=None):
            return container.encrypt_stream(src, dst, master,
                                            progress=progress, cancel=cancel)

        return self.submit(_task, name=f"encrypt:{src}", **kw)

    def decrypt_file(self, src, dst, master, **kw) -> Job:
        from ..core import container

        def _task(progress=None, cancel=None):
            return container.decrypt_stream(src, dst, master,
                                            progress=progress, cancel=cancel)

        return self.submit(_task, name=f"decrypt:{src}", **kw)
