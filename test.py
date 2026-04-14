import argparse
import logging
import time
import uuid
from contextlib import nullcontext

from observability import (
    DEFAULT_CONFIG_PATH,
    configure_logging,
    configure_tracing,
    emit_sampling_decision,
    export_metrics,
    get_current_span,
    get_current_trace_context,
    get_logger,
    get_metrics_snapshot,
    get_tracer,
    load_config,
    log_duration,
    reload_sampling_config_if_needed,
    record_metrics,
)


def parse_args():
    parser = argparse.ArgumentParser(description="Build a greeting message.")
    parser.add_argument("--name", help="Name to greet.")
    parser.add_argument("--age", help="Age to include in the greeting.")
    parser.add_argument("--request-id", help="Correlation ID to include in logs.")
    parser.add_argument("--config", default=str(DEFAULT_CONFIG_PATH), help="Path to YAML config.")
    args = parser.parse_args()
    return args


@log_duration
def get_name(raw_name, logger):
    logger.debug("Entering get_name")
    if raw_name is None or not raw_name.strip():
        logger.info("No name provided; using default name.")
        logger.debug("Exiting get_name")
        return "friend"

    logger.info("Collected name argument.")
    logger.debug("Exiting get_name")
    return raw_name.strip()


@log_duration
def get_age(raw_age, logger):
    logger.debug("Entering get_age")
    if raw_age is None or not raw_age.strip():
        logger.info("No age provided; age will be skipped.")
        logger.debug("Exiting get_age")
        return None

    try:
        age = int(raw_age.strip())
    except ValueError:
        logger.warning("Received non-numeric age input: %r", raw_age)
        print("That was not a valid number, so age will be skipped.")
        logger.debug("Exiting get_age")
        return None

    if age < 0 or age > 120:
        logger.warning("Received out-of-range age input: %s", age)
        print("Age must be between 0 and 120, so age will be skipped.")
        logger.debug("Exiting get_age")
        return None

    logger.info("Collected valid age input.")
    logger.debug("Exiting get_age")
    return age


@log_duration
def build_message(name, age, logger):
    logger.debug("Entering build_message")
    if age is None:
        logger.info("Building greeting without age.")
        logger.debug("Exiting build_message")
        return f"Hello, {name}. Nice to meet you."
    logger.info("Building greeting with age.")
    logger.debug("Exiting build_message")
    return f"Hello, {name}. You are {age} years old."


def main():
    args = parse_args()
    config = load_config(args.config)
    configure_logging(config, args.config)
    configure_tracing(config)
    request_id = args.request_id or str(uuid.uuid4())
    tracer = get_tracer()
    root_span_context_manager = tracer.start_as_current_span("main") if tracer else nullcontext()
    with root_span_context_manager:
        trace_id, span_id = get_current_trace_context()
        request_id = trace_id or request_id
        current_span = get_current_span()
        if current_span is not None:
            current_span.set_attribute("app.request_id", request_id)
            current_span.set_attribute("code.function", "main")
        logger = get_logger(
            request_id,
            config["service"]["environment"],
            config["service"]["version"],
            trace_id=trace_id,
            span_id=span_id,
        )
        emit_sampling_decision(logger, request_id, "main")
        start = time.perf_counter()
        logger.debug("Entering main")
        try:
            reload_sampling_config_if_needed()
            logger.info("Starting greeting script.")
            name = get_name(args.name, logger)
            age = get_age(args.age, logger)
            message = build_message(name, age, logger)
            logger.info("Printing final greeting.")
            print(message)
        except Exception:
            logger.exception("Unhandled exception in main.")
            raise
        finally:
            duration_ms = round((time.perf_counter() - start) * 1000, 3)
            record_metrics("main", duration_ms)
            current_span = get_current_span()
            if current_span is not None:
                current_span.set_attribute("app.duration_ms", duration_ms)
            logger.info(
                "Function execution completed.",
                extra={"duration_ms": duration_ms, "measured_function": "main"},
            )
            logger.info(
                "Metrics snapshot collected.",
                extra={
                    "metrics": get_metrics_snapshot(
                        config["service"]["environment"],
                        config["service"]["version"],
                        request_id,
                    ),
                    "event_type": "metrics",
                    "metric_type": "summary",
                    "metric_source": "in_process_collector",
                },
            )
            export_metrics(
                config,
                get_metrics_snapshot(
                    config["service"]["environment"],
                    config["service"]["version"],
                    request_id,
                ),
                logger,
            )
            logger.debug("Exiting main")


if __name__ == "__main__":
    main()
