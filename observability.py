import functools
import hashlib
import json
import logging
import random
import time
import urllib.error
import urllib.request
from contextlib import nullcontext
from logging.handlers import RotatingFileHandler
from pathlib import Path

import yaml

try:
    from opentelemetry import trace
    from opentelemetry.sdk.resources import Resource
    from opentelemetry.sdk.trace import TracerProvider

    OPENTELEMETRY_AVAILABLE = True
except ImportError:
    trace = None
    Resource = None
    TracerProvider = None
    OPENTELEMETRY_AVAILABLE = False


TRACER = None
CURRENT_CONFIG_PATH = None
LAST_SAMPLING_MTIME = None
SAMPLING = {
    "logs": {
        "enabled": False,
        "rate": 1.0,
        "exclude_event_types": ["metrics", "metrics_export"],
        "adaptive": {
            "enabled": False,
            "error_rate_threshold": 0.1,
            "latency_p95_threshold_ms": 250,
            "elevated_rate": 1.0,
        },
    },
    "metrics": {
        "enabled": False,
        "rate": 1.0,
        "adaptive": {
            "enabled": False,
            "error_rate_threshold": 0.1,
            "latency_p95_threshold_ms": 250,
            "elevated_rate": 1.0,
        },
    },
}
METRICS = {
    "execution_counts": {},
    "execution_durations_ms": {},
    "execution_timestamps": {},
    "error_counts": {},
    "sampling_decisions": {"keep": 0, "drop": 0},
    "dropped_request_ids": [],
}
MAX_DURATION_SAMPLES = 100
MAX_DROPPED_REQUEST_IDS = 100
HISTOGRAM_BUCKETS_MS = [1, 5, 10, 25, 50, 100, 250, 500, 1000]
DEFAULT_CONFIG_PATH = Path(__file__).with_name("observability.yaml")


class ContextLoggerAdapter(logging.LoggerAdapter):
    def process(self, msg, kwargs):
        extra = {**self.extra, **kwargs.get("extra", {})}
        start_time = extra.get("_duration_start")
        if start_time is not None and "duration_ms" not in extra:
            extra["duration_ms"] = round((time.perf_counter() - start_time) * 1000, 3)
        kwargs["extra"] = extra
        return msg, kwargs


class SamplingFilter(logging.Filter):
    def filter(self, record):
        reload_sampling_config_if_needed()
        if not SAMPLING["logs"]["enabled"]:
            return True
        if record.levelno >= logging.ERROR:
            return True
        event_type = getattr(record, "event_type", "log")
        if event_type == "sampling_decision":
            return True
        if event_type in SAMPLING["logs"].get("exclude_event_types", []):
            return True
        function_name = getattr(record, "measured_function", None) or getattr(
            record, "funcName", None
        )
        sampling_rate = get_sampling_rate("logs", function_name)
        request_id = getattr(record, "request_id", None)
        if request_id:
            return should_sample_request(request_id, sampling_rate)
        return random.random() < sampling_rate


class JsonFormatter(logging.Formatter):
    def __init__(self, telemetry_config):
        super().__init__()
        self.telemetry_config = telemetry_config

    def format(self, record):
        timestamp = self.formatTime(record, "%Y-%m-%dT%H:%M:%S")
        timestamp = f"{timestamp}.{int(record.msecs):03d}Z"
        payload = {
            "@timestamp": timestamp,
            "TimeGenerated": timestamp,
            "message": record.getMessage(),
            "Message": record.getMessage(),
            "event.type": getattr(record, "event_type", "log"),
            "EventType": getattr(record, "event_type", "log"),
            "sampling.decision": getattr(record, "sampling_decision", None),
            "SamplingDecision": getattr(record, "sampling_decision", None),
            "sampling.rate": getattr(record, "sampling_rate", None),
            "SamplingRate": getattr(record, "sampling_rate", None),
            "metric.type": getattr(record, "metric_type", None),
            "MetricType": getattr(record, "metric_type", None),
            "metric.source": getattr(record, "metric_source", None),
            "MetricSource": getattr(record, "metric_source", None),
            "log.level": record.levelname,
            "Level": record.levelname,
            "log.logger": record.name,
            "LoggerName": record.name,
            "service.environment": getattr(record, "environment", None),
            "Environment": getattr(record, "environment", None),
            "service.version": getattr(record, "app_version", None),
            "AppVersion": getattr(record, "app_version", None),
            "event.dataset": self.telemetry_config["dataset"],
            "EventDataset": self.telemetry_config["dataset"],
            "labels.request_id": getattr(record, "request_id", None),
            "RequestId": getattr(record, "request_id", None),
            "trace.id": getattr(record, "trace_id", None),
            "TraceId": getattr(record, "trace_id", None),
            "labels.span_id": getattr(record, "span_id", None),
            "SpanId": getattr(record, "span_id", None),
            "labels.parent_span_id": getattr(record, "parent_span_id", None),
            "ParentSpanId": getattr(record, "parent_span_id", None),
            "labels.measured_function": getattr(record, "measured_function", None),
            "MeasuredFunction": getattr(record, "measured_function", None),
            "event.duration_ms": getattr(record, "duration_ms", None),
            "DurationMs": getattr(record, "duration_ms", None),
            "metrics": getattr(record, "metrics", None),
            "process.pid": record.process,
            "ProcessId": record.process,
            "process.name": record.processName,
            "ProcessName": record.processName,
            "process.thread.id": record.thread,
            "ThreadId": record.thread,
            "process.thread.name": record.threadName,
            "ThreadName": record.threadName,
            "log.origin.file.name": record.filename,
            "FileName": record.filename,
            "log.origin.file.line": record.lineno,
            "LineNumber": record.lineno,
            "log.origin.file.path": record.pathname,
            "FilePath": record.pathname,
            "log.origin.function": record.funcName,
            "FunctionName": record.funcName,
            "python.module": record.module,
            "Module": record.module,
        }
        if record.exc_text:
            payload["error.stack_trace"] = record.exc_text
            payload["Exception"] = record.exc_text
        if record.stack_info:
            payload["error.stack_trace"] = self.formatStack(record.stack_info)
            payload["Exception"] = payload["error.stack_trace"]
        if record.exc_info:
            payload["error.stack_trace"] = self.formatException(record.exc_info)
            payload["error.type"] = record.exc_info[0].__name__
            payload["Exception"] = payload["error.stack_trace"]
            payload["ExceptionType"] = record.exc_info[0].__name__
        return json.dumps(payload)


def get_current_trace_context():
    if not OPENTELEMETRY_AVAILABLE:
        return None, None
    span = trace.get_current_span()
    span_context = span.get_span_context()
    if not span_context.is_valid:
        return None, None
    return f"{span_context.trace_id:032x}", f"{span_context.span_id:016x}"


def get_current_span():
    if not OPENTELEMETRY_AVAILABLE:
        return None
    span = trace.get_current_span()
    span_context = span.get_span_context()
    if not span_context.is_valid:
        return None
    return span


def get_tracer():
    return TRACER


def load_config(config_path):
    with Path(config_path).open("r", encoding="utf-8") as config_file:
        return yaml.safe_load(config_file)


def apply_sampling_config(config):
    sampling_config = config.get("sampling", {})
    SAMPLING["logs"] = {
        "enabled": sampling_config.get("logs", {}).get("enabled", False),
        "rate": sampling_config.get("logs", {}).get("rate", 1.0),
        "exclude_event_types": sampling_config.get("logs", {}).get(
            "exclude_event_types", ["metrics", "metrics_export"]
        ),
        "adaptive": {
            "enabled": sampling_config.get("logs", {}).get("adaptive", {}).get("enabled", False),
            "error_rate_threshold": sampling_config.get("logs", {})
            .get("adaptive", {})
            .get("error_rate_threshold", 0.1),
            "latency_p95_threshold_ms": sampling_config.get("logs", {})
            .get("adaptive", {})
            .get("latency_p95_threshold_ms", 250),
            "elevated_rate": sampling_config.get("logs", {})
            .get("adaptive", {})
            .get("elevated_rate", 1.0),
        },
        "per_function": sampling_config.get("logs", {}).get("per_function", {}),
    }
    SAMPLING["metrics"] = {
        "enabled": sampling_config.get("metrics", {}).get("enabled", False),
        "rate": sampling_config.get("metrics", {}).get("rate", 1.0),
        "adaptive": {
            "enabled": sampling_config.get("metrics", {}).get("adaptive", {}).get("enabled", False),
            "error_rate_threshold": sampling_config.get("metrics", {})
            .get("adaptive", {})
            .get("error_rate_threshold", 0.1),
            "latency_p95_threshold_ms": sampling_config.get("metrics", {})
            .get("adaptive", {})
            .get("latency_p95_threshold_ms", 250),
            "elevated_rate": sampling_config.get("metrics", {})
            .get("adaptive", {})
            .get("elevated_rate", 1.0),
        },
        "per_function": sampling_config.get("metrics", {}).get("per_function", {}),
    }


def reload_sampling_config_if_needed(config_path=None, force=False):
    global CURRENT_CONFIG_PATH, LAST_SAMPLING_MTIME
    effective_path = Path(config_path or CURRENT_CONFIG_PATH) if (config_path or CURRENT_CONFIG_PATH) else None
    if effective_path is None or not effective_path.exists():
        return False

    current_mtime = effective_path.stat().st_mtime
    if not force and LAST_SAMPLING_MTIME is not None and current_mtime <= LAST_SAMPLING_MTIME:
        return False

    config = load_config(effective_path)
    apply_sampling_config(config)
    CURRENT_CONFIG_PATH = effective_path
    LAST_SAMPLING_MTIME = current_mtime
    return True


def record_metrics(function_name, duration_ms):
    reload_sampling_config_if_needed()
    if SAMPLING["metrics"]["enabled"] and random.random() >= get_sampling_rate(
        "metrics", function_name
    ):
        return
    METRICS["execution_counts"][function_name] = (
        METRICS["execution_counts"].get(function_name, 0) + 1
    )
    durations = METRICS["execution_durations_ms"].setdefault(function_name, [])
    timestamps = METRICS["execution_timestamps"].setdefault(function_name, [])
    durations.append(duration_ms)
    timestamps.append(time.time())
    if len(durations) > MAX_DURATION_SAMPLES:
        del durations[:-MAX_DURATION_SAMPLES]
    if len(timestamps) > MAX_DURATION_SAMPLES:
        del timestamps[:-MAX_DURATION_SAMPLES]


def record_error(function_name):
    reload_sampling_config_if_needed()
    if SAMPLING["metrics"]["enabled"] and random.random() >= get_sampling_rate(
        "metrics", function_name
    ):
        return
    METRICS["error_counts"][function_name] = METRICS["error_counts"].get(function_name, 0) + 1


def record_sampling_decision(decision):
    if decision not in METRICS["sampling_decisions"]:
        METRICS["sampling_decisions"][decision] = 0
    METRICS["sampling_decisions"][decision] += 1


def record_dropped_request_id(request_id):
    if not request_id:
        return
    dropped_request_ids = METRICS["dropped_request_ids"]
    dropped_request_ids.append(request_id)
    if len(dropped_request_ids) > MAX_DROPPED_REQUEST_IDS:
        del dropped_request_ids[:-MAX_DROPPED_REQUEST_IDS]


def percentile(values, percentile_rank):
    if not values:
        return None
    sorted_values = sorted(values)
    index = max(0, min(len(sorted_values) - 1, int((len(sorted_values) - 1) * percentile_rank)))
    return sorted_values[index]


def get_function_error_rate(function_name):
    count = METRICS["execution_counts"].get(function_name, 0)
    if count == 0:
        return 0.0
    return METRICS["error_counts"].get(function_name, 0) / count


def get_function_p95_latency(function_name):
    durations = METRICS["execution_durations_ms"].get(function_name, [])
    return percentile(durations, 0.95) or 0


def get_sampling_rate(kind, function_name=None):
    config = SAMPLING[kind]
    base_rate = config["rate"]
    adaptive = config.get("adaptive", {})
    if function_name is not None:
        function_config = config.get("per_function", {}).get(function_name, {})
        base_rate = function_config.get("rate", base_rate)
        adaptive = {
            **adaptive,
            **function_config.get("adaptive", {}),
        }
    if not adaptive.get("enabled"):
        return base_rate

    if function_name is None:
        function_names = set(METRICS["execution_counts"]) | set(METRICS["error_counts"])
        error_rate = max((get_function_error_rate(name) for name in function_names), default=0.0)
        latency_p95 = max((get_function_p95_latency(name) for name in function_names), default=0)
    else:
        error_rate = get_function_error_rate(function_name)
        latency_p95 = get_function_p95_latency(function_name)

    if (
        error_rate >= adaptive.get("error_rate_threshold", 1.0)
        or latency_p95 >= adaptive.get("latency_p95_threshold_ms", float("inf"))
    ):
        return max(base_rate, adaptive.get("elevated_rate", base_rate))
    return base_rate


def should_sample_request(request_id, sample_rate):
    if sample_rate >= 1.0:
        return True
    if sample_rate <= 0.0:
        return False
    digest = hashlib.sha256(str(request_id).encode("utf-8")).hexdigest()
    normalized = int(digest[:8], 16) / 0xFFFFFFFF
    return normalized < sample_rate


def get_request_sampling_decision(request_id, function_name=None):
    sampling_rate = get_sampling_rate("logs", function_name)
    decision = should_sample_request(request_id, sampling_rate)
    if not decision:
        record_dropped_request_id(request_id)
    return {"decision": "keep" if decision else "drop", "rate": sampling_rate}


def build_histogram(values):
    histogram = {f"le_{bucket}ms": 0 for bucket in HISTOGRAM_BUCKETS_MS}
    histogram["gt_1000ms"] = 0
    for value in values:
        placed = False
        for bucket in HISTOGRAM_BUCKETS_MS:
            if value <= bucket:
                histogram[f"le_{bucket}ms"] += 1
                placed = True
                break
        if not placed:
            histogram["gt_1000ms"] += 1
    return histogram


def sanitize_metric_name(name):
    return "".join(character if character.isalnum() else "_" for character in name).strip("_")


def build_prometheus_metrics(environment=None, version=None, request_id=None):
    metrics = []
    total_sampling = sum(METRICS["sampling_decisions"].values())
    if total_sampling:
        keep_rate = round(METRICS["sampling_decisions"].get("keep", 0) / total_sampling, 4)
        drop_rate = round(METRICS["sampling_decisions"].get("drop", 0) / total_sampling, 4)
        metrics.extend(
            [
                {
                    "name": "greeting_app_sampling_keep_rate",
                    "labels": {
                        "environment": environment,
                        "version": version,
                        "request_id": request_id,
                    },
                    "value": keep_rate,
                    "type": "gauge",
                },
                {
                    "name": "greeting_app_sampling_drop_rate",
                    "labels": {
                        "environment": environment,
                        "version": version,
                        "request_id": request_id,
                    },
                    "value": drop_rate,
                    "type": "gauge",
                },
            ]
        )
    for function_name, count in METRICS["execution_counts"].items():
        metric_function = sanitize_metric_name(function_name)
        durations = METRICS["execution_durations_ms"].get(function_name, [])
        base_labels = {
            "function": metric_function,
            "environment": environment,
            "version": version,
            "request_id": request_id,
        }
        summary = {
            "avg": round(sum(durations) / len(durations), 3) if durations else 0,
            "p95": percentile(durations, 0.95),
            "p99": percentile(durations, 0.99),
            "error_rate": round(METRICS["error_counts"].get(function_name, 0) / count, 4),
        }
        metrics.extend(
            [
                {
                    "name": "greeting_app_function_execution_total",
                    "labels": base_labels,
                    "value": count,
                    "type": "counter",
                },
                {
                    "name": "greeting_app_function_error_total",
                    "labels": base_labels,
                    "value": METRICS["error_counts"].get(function_name, 0),
                    "type": "counter",
                },
                {
                    "name": "greeting_app_function_error_rate",
                    "labels": base_labels,
                    "value": summary["error_rate"],
                    "type": "gauge",
                },
                {
                    "name": "greeting_app_function_duration_avg_ms",
                    "labels": base_labels,
                    "value": summary["avg"],
                    "type": "gauge",
                },
                {
                    "name": "greeting_app_function_duration_p95_ms",
                    "labels": base_labels,
                    "value": summary["p95"],
                    "type": "gauge",
                },
                {
                    "name": "greeting_app_function_duration_p99_ms",
                    "labels": base_labels,
                    "value": summary["p99"],
                    "type": "gauge",
                },
            ]
        )
        histogram = build_histogram(durations)
        for bucket_name, bucket_value in histogram.items():
            metrics.append(
                {
                    "name": "greeting_app_function_duration_bucket_ms",
                    "labels": {**base_labels, "bucket": bucket_name},
                    "value": bucket_value,
                    "type": "histogram",
                }
            )
    return metrics


def build_azure_monitor_metrics():
    metrics = []
    total_sampling = sum(METRICS["sampling_decisions"].values())
    if total_sampling:
        metrics.append(
            {
                "MetricName": "SamplingDecision",
                "KeepRate": round(METRICS["sampling_decisions"].get("keep", 0) / total_sampling, 4),
                "DropRate": round(METRICS["sampling_decisions"].get("drop", 0) / total_sampling, 4),
                "KeepCount": METRICS["sampling_decisions"].get("keep", 0),
                "DropCount": METRICS["sampling_decisions"].get("drop", 0),
            }
        )
    for function_name, count in METRICS["execution_counts"].items():
        durations = METRICS["execution_durations_ms"].get(function_name, [])
        histogram = build_histogram(durations)
        metrics.append(
            {
                "MetricName": "FunctionExecution",
                "FunctionName": function_name,
                "Count": count,
                "ErrorCount": METRICS["error_counts"].get(function_name, 0),
                "ErrorRate": round(METRICS["error_counts"].get(function_name, 0) / count, 4),
                "AvgDurationMs": round(sum(durations) / len(durations), 3) if durations else 0,
                "P95DurationMs": percentile(durations, 0.95),
                "P99DurationMs": percentile(durations, 0.99),
                "Histogram": histogram,
            }
        )
    return metrics


def format_prometheus_labels(labels):
    parts = []
    for key, value in labels.items():
        if value is None:
            continue
        escaped = str(value).replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")
        parts.append(f'{key}="{escaped}"')
    return ",".join(parts)


def build_prometheus_payload(metrics, job_name):
    lines = [f"# job={job_name}"]
    for metric in metrics:
        labels = format_prometheus_labels(metric.get("labels", {}))
        label_suffix = f"{{{labels}}}" if labels else ""
        value = 0 if metric["value"] is None else metric["value"]
        lines.append(f'{metric["name"]}{label_suffix} {value}')
    return "\n".join(lines) + "\n"


def post_payload(url, payload, content_type, timeout_seconds, headers=None):
    request_headers = {"Content-Type": content_type, **(headers or {})}
    request = urllib.request.Request(
        url,
        data=payload,
        headers=request_headers,
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=timeout_seconds):
        return


def export_prometheus_metrics(config, metrics_snapshot, logger=None):
    exporter_config = config.get("exporters", {}).get("prometheus", {})
    gateway_url = exporter_config.get("gateway_url")
    if not exporter_config.get("enabled") or not gateway_url:
        return

    payload = build_prometheus_payload(
        metrics_snapshot["prometheus_metrics"],
        exporter_config.get("job", "greeting_app"),
    ).encode("utf-8")
    try:
        post_payload(
            gateway_url,
            payload,
            "text/plain; version=0.0.4",
            exporter_config.get("timeout_seconds", 5),
            exporter_config.get("headers"),
        )
        if logger is not None:
            logger.info(
                "Prometheus metrics exported.",
                extra={"event_type": "metrics_export", "metric_source": "prometheus_pushgateway"},
            )
    except (urllib.error.URLError, OSError) as exc:
        if logger is not None:
            logger.warning(
                "Prometheus metrics export failed: %s",
                exc,
                extra={"event_type": "metrics_export", "metric_source": "prometheus_pushgateway"},
            )


def export_azure_monitor_metrics(config, metrics_snapshot, logger=None):
    exporter_config = config.get("exporters", {}).get("azure_monitor", {})
    endpoint = exporter_config.get("endpoint")
    if not exporter_config.get("enabled") or not endpoint:
        return

    payload = json.dumps(metrics_snapshot["azure_monitor_metrics"]).encode("utf-8")
    try:
        post_payload(
            endpoint,
            payload,
            "application/json",
            exporter_config.get("timeout_seconds", 5),
            exporter_config.get("headers"),
        )
        if logger is not None:
            logger.info(
                "Azure metrics exported.",
                extra={"event_type": "metrics_export", "metric_source": "azure_monitor_api"},
            )
    except (urllib.error.URLError, OSError) as exc:
        if logger is not None:
            logger.warning(
                "Azure metrics export failed: %s",
                exc,
                extra={"event_type": "metrics_export", "metric_source": "azure_monitor_api"},
            )


def export_metrics(config, metrics_snapshot, logger=None):
    export_prometheus_metrics(config, metrics_snapshot, logger)
    export_azure_monitor_metrics(config, metrics_snapshot, logger)


def get_metrics_snapshot(environment=None, version=None, request_id=None):
    all_timestamps = [
        timestamp
        for timestamps in METRICS["execution_timestamps"].values()
        for timestamp in timestamps
    ]
    return {
        "execution_counts": dict(METRICS["execution_counts"]),
        "error_counts": dict(METRICS["error_counts"]),
        "sampling_decisions": dict(METRICS["sampling_decisions"]),
        "sampling_keep_count": METRICS["sampling_decisions"].get("keep", 0),
        "sampling_drop_count": METRICS["sampling_decisions"].get("drop", 0),
        "dropped_request_ids": list(METRICS["dropped_request_ids"]),
        "sampling_keep_rate": round(
            METRICS["sampling_decisions"].get("keep", 0)
            / max(1, sum(METRICS["sampling_decisions"].values())),
            4,
        ),
        "sampling_drop_rate": round(
            METRICS["sampling_decisions"].get("drop", 0)
            / max(1, sum(METRICS["sampling_decisions"].values())),
            4,
        ),
        "metrics_window_start": (
            time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(min(all_timestamps))) + "Z"
            if all_timestamps
            else None
        ),
        "metrics_window_end": (
            time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(max(all_timestamps))) + "Z"
            if all_timestamps
            else None
        ),
        "execution_summary_ms": {
            name: {
                "avg": round(sum(durations) / len(durations), 3),
                "p95": percentile(durations, 0.95),
                "p99": percentile(durations, 0.99),
                "error_rate": round(
                    METRICS["error_counts"].get(name, 0) / METRICS["execution_counts"][name], 4
                ),
                "histogram": build_histogram(durations),
            }
            for name, durations in METRICS["execution_durations_ms"].items()
        },
        "execution_durations_ms": {
            name: list(durations)
            for name, durations in METRICS["execution_durations_ms"].items()
        },
        "prometheus_metrics": build_prometheus_metrics(environment, version, request_id),
        "azure_monitor_metrics": build_azure_monitor_metrics(),
    }


def log_duration(func):
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        logger = kwargs.get("logger")
        if logger is None and args and isinstance(args[-1], logging.LoggerAdapter):
            logger = args[-1]
        tracer = get_tracer()
        span_context_manager = tracer.start_as_current_span(func.__name__) if tracer else nullcontext()
        start = time.perf_counter()
        with span_context_manager:
            span_logger = logger
            if logger is not None:
                trace_id, span_id = get_current_trace_context()
                current_span = get_current_span()
                if current_span is not None:
                    request_id = trace_id or logger.extra.get("request_id")
                    current_span.set_attribute("app.request_id", request_id)
                    current_span.set_attribute("code.function", func.__name__)
                span_logger = ContextLoggerAdapter(
                    logger.logger,
                    {
                        **logger.extra,
                        "request_id": trace_id or logger.extra.get("request_id"),
                        "trace_id": trace_id,
                        "span_id": span_id,
                        "parent_span_id": logger.extra.get("span_id"),
                        "measured_function": func.__name__,
                        "_duration_start": start,
                    },
                )
                if "logger" in kwargs:
                    kwargs["logger"] = span_logger
                elif args and isinstance(args[-1], logging.LoggerAdapter):
                    args = (*args[:-1], span_logger)
            try:
                return func(*args, **kwargs)
            except Exception:
                record_error(func.__name__)
                raise
            finally:
                duration_ms = round((time.perf_counter() - start) * 1000, 3)
                record_metrics(func.__name__, duration_ms)
                current_span = get_current_span()
                if current_span is not None:
                    current_span.set_attribute("app.duration_ms", duration_ms)
                if span_logger is not None:
                    span_logger.info(
                        "Function execution completed.",
                        extra={"duration_ms": duration_ms, "measured_function": func.__name__},
                    )

    return wrapper


def configure_logging(config, config_path=None):
    global CURRENT_CONFIG_PATH, LAST_SAMPLING_MTIME
    apply_sampling_config(config)
    if config_path is not None:
        CURRENT_CONFIG_PATH = Path(config_path)
        if CURRENT_CONFIG_PATH.exists():
            LAST_SAMPLING_MTIME = CURRENT_CONFIG_PATH.stat().st_mtime
    logging_config = config["logging"]
    numeric_level = getattr(logging, logging_config["level"].upper(), logging.INFO)
    formatter = JsonFormatter(config["telemetry"])
    stream_handler = logging.StreamHandler()
    stream_handler.addFilter(SamplingFilter())
    stream_handler.setFormatter(formatter)
    file_handler = RotatingFileHandler(
        logging_config["file"],
        maxBytes=logging_config["max_bytes"],
        backupCount=logging_config["backup_count"],
    )
    file_handler.addFilter(SamplingFilter())
    file_handler.setFormatter(formatter)
    logging.basicConfig(level=numeric_level, handlers=[stream_handler, file_handler])


def configure_tracing(config):
    global TRACER
    if not config["telemetry"]["enabled"] or not OPENTELEMETRY_AVAILABLE:
        TRACER = None
        return

    resource = Resource.create(
        {
            "service.name": config["service"]["name"],
            "service.version": config["service"]["version"],
            "deployment.environment": config["service"]["environment"],
        }
    )
    trace.set_tracer_provider(TracerProvider(resource=resource))
    TRACER = trace.get_tracer(__name__)


def get_logger(request_id, environment, app_version, trace_id=None, span_id=None, parent_span_id=None):
    return ContextLoggerAdapter(
        logging.getLogger(__name__),
        {
            "request_id": request_id,
            "environment": environment,
            "app_version": app_version,
            "trace_id": trace_id,
            "span_id": span_id,
            "parent_span_id": parent_span_id,
        },
    )


def emit_sampling_decision(logger, request_id, function_name=None):
    sampling = get_request_sampling_decision(request_id, function_name)
    record_sampling_decision(sampling["decision"])
    logger.info(
        "Sampling decision evaluated.",
        extra={
            "event_type": "sampling_decision",
            "sampling_decision": sampling["decision"],
            "sampling_rate": sampling["rate"],
        },
    )
    logger.extra["sampling_decision"] = sampling["decision"]
    logger.extra["sampling_rate"] = sampling["rate"]
    return sampling
