#!/usr/bin/env python3
"""
Generate a Markdown tuning snapshot for bot blocker parameter analysis.

This script summarizes a log window in a compact format intended for human
review or LLM-assisted parameter tuning.
"""
import argparse
import ipaddress
import logging
import math
import os
import shlex
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import psutil

from parser import _read_lines_reverse
from threat_analyzer import ThreatAnalyzer
from strategies.unified import Strategy


LOG_FORMAT = "%(asctime)s %(levelname)s %(name)s: %(message)s"
LOG_DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
DEFAULT_ACCESS_LOG = "/var/log/httpd/access_log"

DEFAULT_MIN_RPM_THRESHOLD = 10.0
DEFAULT_MIN_SUSTAINED_PERCENT = 25.0
DEFAULT_MAX_CPU_LOAD_THRESHOLD = 80.0
DEFAULT_IP_SWARM_THRESHOLD = 40
DEFAULT_IP_SWARM_RPM_FACTOR = 0.60
DEFAULT_IP_SWARM_BONUS_MAX = 1.50
DEFAULT_IP_MIN_RPM_THRESHOLD = 20.0
DEFAULT_IP_MIN_SUSTAINED_PERCENT = 35.0
DEFAULT_IP_MIN_REQUESTS = 120
DEFAULT_SUPERNET_MIN_RPM_TOTAL = 6.0
DEFAULT_SUPERNET_MIN_IP_COUNT = 120
DEFAULT_SUPERNET_MIN_REQUESTS = 200

BASELINE_PRESETS = {
    "lareferencia-hourly": {
        "label": "LA Referencia hourly baseline",
        "min_rpm_threshold": 6.0,
        "min_sustained_percent": 20.0,
        "max_cpu_load_threshold": 75.0,
        "ip_swarm_threshold": 30,
        "ip_swarm_rpm_factor": 0.45,
        "ip_swarm_bonus_max": 2.0,
        "ip_min_rpm_threshold": 20.0,
        "ip_min_sustained_percent": 35.0,
        "ip_min_requests": 120,
        "supernet_min_rpm_total": 5.5,
        "supernet_min_ip_count": 100,
        "supernet_min_requests": 180,
    },
    "repo-defaults": {
        "label": "Repository defaults",
        "min_rpm_threshold": DEFAULT_MIN_RPM_THRESHOLD,
        "min_sustained_percent": DEFAULT_MIN_SUSTAINED_PERCENT,
        "max_cpu_load_threshold": DEFAULT_MAX_CPU_LOAD_THRESHOLD,
        "ip_swarm_threshold": DEFAULT_IP_SWARM_THRESHOLD,
        "ip_swarm_rpm_factor": DEFAULT_IP_SWARM_RPM_FACTOR,
        "ip_swarm_bonus_max": DEFAULT_IP_SWARM_BONUS_MAX,
        "ip_min_rpm_threshold": DEFAULT_IP_MIN_RPM_THRESHOLD,
        "ip_min_sustained_percent": DEFAULT_IP_MIN_SUSTAINED_PERCENT,
        "ip_min_requests": DEFAULT_IP_MIN_REQUESTS,
        "supernet_min_rpm_total": DEFAULT_SUPERNET_MIN_RPM_TOTAL,
        "supernet_min_ip_count": DEFAULT_SUPERNET_MIN_IP_COUNT,
        "supernet_min_requests": DEFAULT_SUPERNET_MIN_REQUESTS,
    },
}

CRON_FLAG_MAP = {
    "--min-rpm-threshold": ("min_rpm_threshold", float),
    "--min-sustained-percent": ("min_sustained_percent", float),
    "--max-cpu-load-threshold": ("max_cpu_load_threshold", float),
    "--ip-swarm-threshold": ("ip_swarm_threshold", int),
    "--ip-swarm-rpm-factor": ("ip_swarm_rpm_factor", float),
    "--ip-swarm-bonus-max": ("ip_swarm_bonus_max", float),
    "--ip-min-rpm-threshold": ("ip_min_rpm_threshold", float),
    "--ip-min-sustained-percent": ("ip_min_sustained_percent", float),
    "--ip-min-requests": ("ip_min_requests", int),
    "--supernet-min-rpm-total": ("supernet_min_rpm_total", float),
    "--supernet-min-ip-count": ("supernet_min_ip_count", int),
    "--supernet-min-requests": ("supernet_min_requests", int),
    "--time-window": ("time_window", str),
}

PARAMS_TOKEN_MAP = {
    "rpm_base": ("min_rpm_threshold", float),
    "sust_base": ("min_sustained_percent", float),
    "cpu_thr": ("max_cpu_load_threshold", float),
    "swarm_ips": ("ip_swarm_threshold", int),
    "swarm_rpmf": ("ip_swarm_rpm_factor", float),
    "swarm_bonus": ("ip_swarm_bonus_max", float),
    "ip_rpm_base": ("ip_min_rpm_threshold", float),
    "ip_sust_base": ("ip_min_sustained_percent", float),
    "ip_min_req": ("ip_min_requests", int),
    "super16_rpm": ("supernet_min_rpm_total", float),
    "super16_ips": ("supernet_min_ip_count", int),
    "super16_req": ("supernet_min_requests", int),
    "tw": ("time_window", str),
}


def setup_logging(level_name):
    """Configure console logging."""
    level = getattr(logging, level_name.upper(), logging.INFO)
    logging.basicConfig(level=level, format=LOG_FORMAT, datefmt=LOG_DATE_FORMAT)


def calculate_start_date(time_window):
    """Return local start datetime for a named window."""
    now = datetime.now()
    if time_window == "hour":
        return now - timedelta(hours=1)
    if time_window == "6hour":
        return now - timedelta(hours=6)
    if time_window == "day":
        return now - timedelta(days=1)
    if time_window == "week":
        return now - timedelta(weeks=1)
    return None


def calculate_effective_thresholds(cpu_load_percent, base_min_rpm_threshold,
                                   base_min_sustained_percent, max_cpu_load_threshold):
    """Replicate blocker dynamic threshold behavior."""
    min_rpm_threshold = float(base_min_rpm_threshold)
    min_sustained_percent = float(base_min_sustained_percent)

    if cpu_load_percent >= max_cpu_load_threshold:
        if cpu_load_percent >= 90.0:
            rpm_factor = 0.25
        else:
            rpm_factor = 0.5 - ((cpu_load_percent - max_cpu_load_threshold) / 10.0) * 0.25

        if cpu_load_percent >= 90.0:
            sustained_factor = 0.25 - ((cpu_load_percent - 90.0) / 10.0) * 0.13
            sustained_factor = max(0.12, sustained_factor)
        else:
            sustained_factor = 0.5 - ((cpu_load_percent - max_cpu_load_threshold) / 10.0) * 0.25

        min_rpm_threshold = base_min_rpm_threshold * rpm_factor
        min_sustained_percent = base_min_sustained_percent * sustained_factor

    return min_rpm_threshold, min_sustained_percent


def get_normalized_cpu_load_percent():
    """Return normalized 1-minute load average as percentage, or 0.0."""
    try:
        load_avg_1m = psutil.getloadavg()[0]
        cpu_count = psutil.cpu_count() or 1
        if cpu_count <= 0:
            return 0.0
        return (float(load_avg_1m) / float(cpu_count)) * 100.0
    except Exception:
        return 0.0


def aggregate_ipv4_supernet_pressure(threats):
    """Aggregate /24 threat metrics into /16 metrics."""
    supernet_metrics = {}
    for threat in threats:
        subnet = threat.get("id")
        if not isinstance(subnet, ipaddress.IPv4Network) or subnet.prefixlen != 24:
            continue
        try:
            supernet = subnet.supernet(new_prefix=16)
        except ValueError:
            continue

        metrics = supernet_metrics.setdefault(supernet, {
            "total_requests": 0,
            "total_ips": 0,
            "total_rpm": 0.0,
            "max_subnet_time_span": 0.0,
            "active_subnets": 0,
            "member_subnets": [],
        })
        metrics["total_requests"] += int(threat.get("total_requests", 0) or 0)
        metrics["total_ips"] += int(threat.get("ip_count", 0) or 0)
        metrics["total_rpm"] += float(threat.get("subnet_req_per_min_window", 0.0) or 0.0)
        metrics["max_subnet_time_span"] = max(
            metrics["max_subnet_time_span"],
            float(threat.get("subnet_time_span", 0.0) or 0.0)
        )
        metrics["active_subnets"] += 1
        metrics["member_subnets"].append(subnet)
    return supernet_metrics


def build_ip_pressure_metrics(ip_metrics, analysis_duration_seconds):
    """Build normalized per-IP metrics."""
    entries = []
    if not ip_metrics:
        return entries

    window_minutes = (analysis_duration_seconds / 60.0) if analysis_duration_seconds > 0 else 0.0
    for ip_str, metrics in ip_metrics.items():
        try:
            ip_obj = ipaddress.ip_address(ip_str)
        except ValueError:
            continue

        total_requests = int(metrics.get("total_requests", 0) or 0)
        time_span = float(metrics.get("time_span_seconds", 0.0) or 0.0)
        req_per_min_window = (total_requests / window_minutes) if window_minutes > 0 else 0.0
        entries.append({
            "ip_obj": ip_obj,
            "subnet_obj": metrics.get("subnet"),
            "total_requests": total_requests,
            "time_span_seconds": time_span,
            "req_per_min_window": req_per_min_window,
        })
    return entries


def percentile(values, p):
    """Return interpolated percentile for a numeric list."""
    if not values:
        return 0.0
    ordered = sorted(values)
    if len(ordered) == 1:
        return float(ordered[0])
    rank = (p / 100.0) * (len(ordered) - 1)
    lower = int(math.floor(rank))
    upper = int(math.ceil(rank))
    if lower == upper:
        return float(ordered[lower])
    lower_value = float(ordered[lower])
    upper_value = float(ordered[upper])
    weight = rank - lower
    return lower_value + (upper_value - lower_value) * weight


def pct(part, whole):
    """Safe percentage helper."""
    if whole <= 0:
        return 0.0
    return (float(part) / float(whole)) * 100.0


def format_number(value, decimals=2):
    """Render floats compactly for markdown tables."""
    if isinstance(value, int):
        return str(value)
    if abs(value - round(value)) < 1e-9:
        return str(int(round(value)))
    return f"{value:.{decimals}f}"


def metric_percentiles(values):
    """Return percentile summary for a numeric series."""
    return {
        "p50": percentile(values, 50),
        "p90": percentile(values, 90),
        "p95": percentile(values, 95),
        "p99": percentile(values, 99),
        "max": max(values) if values else 0.0,
    }


def build_config_from_preset(preset_name):
    """Build the baseline config from a named internal preset."""
    preset = BASELINE_PRESETS[preset_name].copy()
    preset["baseline_preset"] = preset_name
    preset["baseline_label"] = preset.pop("label")
    preset["profile_name"] = "balanced_a"
    preset["profile_label"] = "Balanced A"
    return SimpleNamespace(**preset)


def clean_numeric_token(raw_value):
    """Normalize PARAMS values like '20.00%' -> '20.00'."""
    value = str(raw_value).strip()
    if value.endswith("%"):
        value = value[:-1]
    return value


def parse_cron_command(command_text):
    """Extract blocker parameters and stdout log target from a cron command line."""
    extracted = {}
    stdout_log = None
    if not command_text:
        return extracted, stdout_log

    try:
        tokens = shlex.split(command_text)
    except ValueError:
        tokens = command_text.split()

    for idx, token in enumerate(tokens):
        if token in (">", ">>", "1>", "1>>"):
            if idx + 1 < len(tokens):
                candidate = tokens[idx + 1].strip()
                if candidate and not candidate.startswith("&"):
                    stdout_log = candidate
            break
        if token.startswith(">>") and len(token) > 2:
            stdout_log = token[2:].strip() or None
            break
        if token.startswith("1>>") and len(token) > 3:
            stdout_log = token[3:].strip() or None
            break
        if token.startswith(">") and len(token) > 1:
            stdout_log = token[1:].strip() or None
            break
        if token.startswith("1>") and len(token) > 2:
            stdout_log = token[2:].strip() or None
            break
        if token.startswith("2>"):
            break
        mapping = CRON_FLAG_MAP.get(token)
        if not mapping:
            continue
        if idx + 1 >= len(tokens):
            continue
        attr_name, caster = mapping
        raw_value = tokens[idx + 1]
        try:
            extracted[attr_name] = caster(raw_value)
        except (TypeError, ValueError):
            continue
    return extracted, stdout_log


def load_cron_command_from_file(filepath):
    """Return the first active cron line that invokes blocker.py."""
    if not filepath or not os.path.exists(filepath):
        return None
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as handle:
            for line in handle:
                stripped = line.strip()
                if not stripped or stripped.startswith("#"):
                    continue
                if "blocker.py" not in stripped:
                    continue
                return stripped
    except Exception:
        return None
    return None


def load_cron_command_from_system():
    """Return the first active blocker.py command from `crontab -l`."""
    try:
        result = subprocess.run(
            ["crontab", "-l"],
            check=False,
            capture_output=True,
            text=True,
            timeout=5
        )
    except Exception:
        return None

    if result.returncode != 0 or not result.stdout:
        return None

    for line in result.stdout.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if "blocker.py" not in stripped:
            continue
        return stripped
    return None


def parse_execution_log(filepath):
    """Extract blocker baseline parameters from the latest PARAMS line."""
    extracted = {}
    if not filepath or not os.path.exists(filepath):
        return extracted

    latest_line = None
    try:
        for line in _read_lines_reverse(filepath):
            if " PARAMS " in line:
                latest_line = line.strip()
                break
    except Exception:
        latest_line = None

    if not latest_line:
        return extracted

    _, params_segment = latest_line.split(" PARAMS ", 1)
    for token in params_segment.split():
        if "=" not in token:
            continue
        key, raw_value = token.split("=", 1)
        mapping = PARAMS_TOKEN_MAP.get(key)
        if not mapping:
            continue
        attr_name, caster = mapping
        raw_value = clean_numeric_token(raw_value)
        try:
            extracted[attr_name] = caster(raw_value)
        except (TypeError, ValueError):
            continue
    return extracted


def build_config_from_sources(args):
    """Build baseline config using execution log > cron > preset precedence."""
    base = vars(build_config_from_preset(args.baseline_preset)).copy()
    sources_used = [f"preset:{args.baseline_preset}"]
    source_time_window = None
    resolved_execution_log = args.execution_log

    cron_command = args.cron_command
    if not cron_command and args.cron_file:
        cron_command = load_cron_command_from_file(args.cron_file)
    if not cron_command:
        cron_command = load_cron_command_from_system()
    cron_values = {}
    cron_stdout_log = None
    if cron_command:
        cron_values, cron_stdout_log = parse_cron_command(cron_command)
    if cron_values:
        if cron_values.get("time_window") in ("hour", "6hour", "day", "week"):
            source_time_window = cron_values["time_window"]
        for key, value in cron_values.items():
            if key == "time_window":
                continue
            base[key] = value
        sources_used.append("cron")
    if not resolved_execution_log and cron_stdout_log:
        resolved_execution_log = cron_stdout_log

    log_values = parse_execution_log(resolved_execution_log) if resolved_execution_log else {}
    if log_values:
        if log_values.get("time_window") in ("hour", "6hour", "day", "week"):
            source_time_window = log_values["time_window"]
        for key, value in log_values.items():
            if key == "time_window":
                continue
            base[key] = value
        sources_used.append("execution-log")

    base["baseline_source_chain"] = " -> ".join(sources_used)
    if "execution-log" in sources_used:
        base["baseline_preset"] = "execution-log"
        base["baseline_label"] = "Derived from latest blocker PARAMS line"
    elif "cron" in sources_used:
        base["baseline_preset"] = "cron"
        base["baseline_label"] = "Derived from cron blocker command"

    return SimpleNamespace(**base), source_time_window, resolved_execution_log


def build_profile_set(base_cfg, profile_set):
    """Return simulated profiles derived from the current baseline."""
    def clone(name, label, delta):
        data = vars(base_cfg).copy()
        data.update(delta)
        data["profile_name"] = name
        data["profile_label"] = label
        return SimpleNamespace(**data)

    profiles = [clone("balanced_a", "Balanced A", {})]

    if profile_set in ("default", "conservative", "extended"):
        profiles.append(clone(
            "conservative_a",
            "Conservative A",
            {
                "min_rpm_threshold": base_cfg.min_rpm_threshold + 1.0,
                "supernet_min_ip_count": int(math.ceil(base_cfg.supernet_min_ip_count * 1.10)),
            }
        ))

    if profile_set in ("default", "extended"):
        profiles.append(clone(
            "balanced_b",
            "Balanced B",
            {
                "min_rpm_threshold": max(0.5, base_cfg.min_rpm_threshold - 0.5),
                "supernet_min_ip_count": max(1, int(math.floor(base_cfg.supernet_min_ip_count * 0.90))),
            }
        ))

    if profile_set in ("default", "aggressive", "extended"):
        profiles.append(clone(
            "aggressive_a",
            "Aggressive A",
            {
                "min_rpm_threshold": max(0.5, base_cfg.min_rpm_threshold - 1.5),
                "ip_swarm_threshold": max(2, base_cfg.ip_swarm_threshold - 10),
                "supernet_min_ip_count": max(1, int(math.floor(base_cfg.supernet_min_ip_count * 0.80))),
                "ip_min_requests": max(1, int(math.floor(base_cfg.ip_min_requests * 0.85))),
            }
        ))

    return profiles


def describe_profile_changes(base_cfg, profile_cfg):
    """Summarize profile delta vs baseline."""
    changes = []
    if profile_cfg.min_rpm_threshold != base_cfg.min_rpm_threshold:
        changes.append(
            f"/24 rpm {format_number(base_cfg.min_rpm_threshold)}->{format_number(profile_cfg.min_rpm_threshold)}"
        )
    if profile_cfg.supernet_min_ip_count != base_cfg.supernet_min_ip_count:
        changes.append(
            f"/16 ips {base_cfg.supernet_min_ip_count}->{profile_cfg.supernet_min_ip_count}"
        )
    if profile_cfg.ip_swarm_threshold != base_cfg.ip_swarm_threshold:
        changes.append(
            f"swarm ips {base_cfg.ip_swarm_threshold}->{profile_cfg.ip_swarm_threshold}"
        )
    if profile_cfg.ip_min_requests != base_cfg.ip_min_requests:
        changes.append(
            f"ip req {base_cfg.ip_min_requests}->{profile_cfg.ip_min_requests}"
        )
    if not changes:
        return "Current baseline"
    return ", ".join(changes)


def evaluate_profiles(analyzer, analysis_duration_seconds, cpu_load_percent,
                      total_overall_requests, profiles):
    """Simulate the provided profiles against current metrics."""
    strategy = Strategy()
    ip_entries = build_ip_pressure_metrics(analyzer.ip_metrics, analysis_duration_seconds)
    results = []

    for profile_cfg in profiles:
        shared_context = {
            "analysis_duration_seconds": analysis_duration_seconds,
            "total_overall_requests": total_overall_requests,
            "cpu_load_percent": cpu_load_percent,
        }

        effective_rpm_threshold, effective_sustained_percent = calculate_effective_thresholds(
            cpu_load_percent,
            profile_cfg.min_rpm_threshold,
            profile_cfg.min_sustained_percent,
            profile_cfg.max_cpu_load_threshold
        )
        effective_ip_rpm_threshold, effective_ip_sustained_percent = calculate_effective_thresholds(
            cpu_load_percent,
            profile_cfg.ip_min_rpm_threshold,
            profile_cfg.ip_min_sustained_percent,
            profile_cfg.max_cpu_load_threshold
        )

        threats = []
        for subnet_obj, metrics in analyzer.subnet_metrics.items():
            threat_data = metrics.copy()
            threat_data["id"] = subnet_obj
            score, should_block, reason = strategy.calculate_threat_score_and_block(
                threat_data=threat_data,
                config=profile_cfg,
                shared_context_params=shared_context
            )
            threats.append({
                "id": subnet_obj,
                "total_requests": int(threat_data.get("total_requests", 0) or 0),
                "ip_count": int(threat_data.get("ip_count", 0) or 0),
                "single_ip": threat_data.get("single_ip"),
                "subnet_time_span": float(threat_data.get("subnet_time_span", 0.0) or 0.0),
                "subnet_req_per_min_window": float(threat_data.get("subnet_req_per_min_window", 0.0) or 0.0),
                "strategy_score": float(score or 0.0),
                "should_block": bool(should_block),
                "block_reason": reason,
            })

        supernet_pressure = aggregate_ipv4_supernet_pressure(threats)
        blocked_supernets = []
        blocked_subnets_direct = []
        blocked_ips = []
        blocked_subnets_via_supernet = set()
        blocked_subnets_direct_set = set()
        blocked_ips_set = set()

        if analysis_duration_seconds > 0 and cpu_load_percent >= profile_cfg.max_cpu_load_threshold:
            min_sustained_seconds = analysis_duration_seconds * (effective_sustained_percent / 100.0)
            for supernet, data in supernet_pressure.items():
                if data["total_rpm"] < profile_cfg.supernet_min_rpm_total:
                    continue
                if data["total_ips"] < profile_cfg.supernet_min_ip_count:
                    continue
                if data["total_requests"] < profile_cfg.supernet_min_requests:
                    continue
                if data["max_subnet_time_span"] < min_sustained_seconds:
                    continue
                blocked_supernets.append((supernet, data))
                for member_subnet in data["member_subnets"]:
                    blocked_subnets_via_supernet.add(member_subnet)

        for threat in threats:
            subnet_obj = threat["id"]
            if subnet_obj in blocked_subnets_via_supernet:
                continue
            if not threat["should_block"]:
                continue

            if threat["ip_count"] == 1 and threat.get("single_ip"):
                try:
                    ip_obj = ipaddress.ip_address(threat["single_ip"])
                except ValueError:
                    blocked_subnets_direct.append(threat)
                    blocked_subnets_direct_set.add(subnet_obj)
                    continue
                if ip_obj not in blocked_ips_set:
                    blocked_ips.append({
                        "ip_obj": ip_obj,
                        "subnet_obj": subnet_obj,
                        "total_requests": threat["total_requests"],
                    })
                    blocked_ips_set.add(ip_obj)
            else:
                blocked_subnets_direct.append(threat)
                blocked_subnets_direct_set.add(subnet_obj)

        if analysis_duration_seconds > 0:
            min_ip_sustained_seconds = analysis_duration_seconds * (effective_ip_sustained_percent / 100.0)
            for entry in ip_entries:
                ip_obj = entry["ip_obj"]
                subnet_obj = entry["subnet_obj"]
                if subnet_obj in blocked_subnets_via_supernet or subnet_obj in blocked_subnets_direct_set:
                    continue
                if ip_obj in blocked_ips_set:
                    continue
                if entry["total_requests"] < profile_cfg.ip_min_requests:
                    continue
                if entry["req_per_min_window"] < effective_ip_rpm_threshold:
                    continue
                if entry["time_span_seconds"] < min_ip_sustained_seconds:
                    continue
                blocked_ips.append({
                    "ip_obj": ip_obj,
                    "subnet_obj": subnet_obj,
                    "total_requests": entry["total_requests"],
                })
                blocked_ips_set.add(ip_obj)

        covered_requests = 0
        coverage_seen_subnets = set()

        for _, data in blocked_supernets:
            covered_requests += data["total_requests"]
            coverage_seen_subnets.update(data["member_subnets"])

        for threat in blocked_subnets_direct:
            subnet_obj = threat["id"]
            if subnet_obj in coverage_seen_subnets:
                continue
            covered_requests += threat["total_requests"]
            coverage_seen_subnets.add(subnet_obj)

        for entry in blocked_ips:
            if entry["subnet_obj"] in coverage_seen_subnets:
                continue
            covered_requests += entry["total_requests"]

        estimated_rules = len(blocked_supernets) + len(blocked_subnets_direct) + len(blocked_ips)
        results.append({
            "profile_name": profile_cfg.profile_name,
            "profile_label": profile_cfg.profile_label,
            "config": profile_cfg,
            "threats": threats,
            "supernet_pressure": supernet_pressure,
            "blocked_supernets": blocked_supernets,
            "blocked_subnets_direct": blocked_subnets_direct,
            "blocked_ips": blocked_ips,
            "estimated_rules": estimated_rules,
            "covered_requests": covered_requests,
            "coverage_percent": pct(covered_requests, total_overall_requests),
            "effective_rpm_threshold": effective_rpm_threshold,
            "effective_sustained_percent": effective_sustained_percent,
            "effective_ip_rpm_threshold": effective_ip_rpm_threshold,
            "effective_ip_sustained_percent": effective_ip_sustained_percent,
        })

    return results


def classify_subnet_near_misses(simulation, analysis_duration_seconds):
    """Summarize why /24 blocking was missed."""
    categories = {
        "Fails only RPM": 0,
        "Fails only sustained": 0,
        "Fails only swarm cardinality": 0,
        "Fails RPM + sustained": 0,
        "Other mixed failures": 0,
    }
    cfg = simulation["config"]
    rpm_threshold = simulation["effective_rpm_threshold"]
    sustained_seconds = analysis_duration_seconds * (simulation["effective_sustained_percent"] / 100.0)
    swarm_rpm_threshold = rpm_threshold * cfg.ip_swarm_rpm_factor

    for threat in simulation["threats"]:
        if threat["should_block"]:
            continue
        rpm_ok = threat["subnet_req_per_min_window"] >= rpm_threshold
        sustained_ok = threat["subnet_time_span"] >= sustained_seconds
        swarm_ips_ok = threat["ip_count"] >= cfg.ip_swarm_threshold
        swarm_rpm_ok = threat["subnet_req_per_min_window"] >= swarm_rpm_threshold

        if sustained_ok and swarm_rpm_ok and not swarm_ips_ok:
            categories["Fails only swarm cardinality"] += 1
        elif not rpm_ok and sustained_ok:
            categories["Fails only RPM"] += 1
        elif rpm_ok and not sustained_ok:
            categories["Fails only sustained"] += 1
        elif not rpm_ok and not sustained_ok:
            categories["Fails RPM + sustained"] += 1
        else:
            categories["Other mixed failures"] += 1
    return categories


def classify_supernet_near_misses(simulation, analysis_duration_seconds, cpu_load_percent):
    """Summarize why /16 blocking was missed."""
    categories = {
        "Fails only total RPM": 0,
        "Fails only IP count": 0,
        "Fails only total requests": 0,
        "Fails only sustained": 0,
        "Mixed failures": 0,
    }
    cfg = simulation["config"]
    if analysis_duration_seconds <= 0 or cpu_load_percent < cfg.max_cpu_load_threshold:
        return categories

    blocked_supernet_ids = {supernet for supernet, _ in simulation["blocked_supernets"]}
    sustained_seconds = analysis_duration_seconds * (simulation["effective_sustained_percent"] / 100.0)
    for supernet, data in simulation["supernet_pressure"].items():
        if supernet in blocked_supernet_ids:
            continue
        failed = []
        if data["total_rpm"] < cfg.supernet_min_rpm_total:
            failed.append("Fails only total RPM")
        if data["total_ips"] < cfg.supernet_min_ip_count:
            failed.append("Fails only IP count")
        if data["total_requests"] < cfg.supernet_min_requests:
            failed.append("Fails only total requests")
        if data["max_subnet_time_span"] < sustained_seconds:
            failed.append("Fails only sustained")
        if len(failed) == 1:
            categories[failed[0]] += 1
        elif failed:
            categories["Mixed failures"] += 1
    return categories


def classify_ip_near_misses(simulation, analyzer, analysis_duration_seconds):
    """Summarize why IP-layer blocking was missed."""
    categories = {
        "Fails only total requests": 0,
        "Fails only RPM": 0,
        "Fails only sustained": 0,
        "Mixed failures": 0,
    }
    if analysis_duration_seconds <= 0:
        return categories

    cfg = simulation["config"]
    ip_entries = build_ip_pressure_metrics(analyzer.ip_metrics, analysis_duration_seconds)
    blocked_supernet_subnets = set()
    for _, data in simulation["blocked_supernets"]:
        blocked_supernet_subnets.update(data["member_subnets"])
    blocked_subnets = {t["id"] for t in simulation["blocked_subnets_direct"]}
    blocked_ips = {entry["ip_obj"] for entry in simulation["blocked_ips"]}
    sustained_seconds = analysis_duration_seconds * (simulation["effective_ip_sustained_percent"] / 100.0)

    for entry in ip_entries:
        if entry["subnet_obj"] in blocked_supernet_subnets or entry["subnet_obj"] in blocked_subnets:
            continue
        if entry["ip_obj"] in blocked_ips:
            continue
        failed = []
        if entry["total_requests"] < cfg.ip_min_requests:
            failed.append("Fails only total requests")
        if entry["req_per_min_window"] < simulation["effective_ip_rpm_threshold"]:
            failed.append("Fails only RPM")
        if entry["time_span_seconds"] < sustained_seconds:
            failed.append("Fails only sustained")
        if len(failed) == 1:
            categories[failed[0]] += 1
        elif failed:
            categories["Mixed failures"] += 1
    return categories


def detect_dominant_pattern(analyzer, total_overall_requests):
    """Classify the window shape in simple operational terms."""
    ip_values = [m["total_requests"] for m in analyzer.ip_metrics.values()] if analyzer.ip_metrics else []
    subnet_values = [m["total_requests"] for m in analyzer.subnet_metrics.values()] if analyzer.subnet_metrics else []
    threat_like = []
    for subnet_obj, metrics in analyzer.subnet_metrics.items():
        row = metrics.copy()
        row["id"] = subnet_obj
        threat_like.append(row)
    supernet_values = [
        m["total_requests"] for m in aggregate_ipv4_supernet_pressure(threat_like).values()
    ] if threat_like else []

    top_ip_share = pct(max(ip_values) if ip_values else 0, total_overall_requests)
    top_subnet_share = pct(max(subnet_values) if subnet_values else 0, total_overall_requests)
    top_supernet_share = pct(max(supernet_values) if supernet_values else 0, total_overall_requests)

    swarmish_subnets = len([
        metrics for metrics in analyzer.subnet_metrics.values()
        if int(metrics.get("ip_count", 0) or 0) >= 3
    ])

    if top_ip_share >= 5.0:
        return "Single-IP concentration"
    if swarmish_subnets >= 10 and top_supernet_share >= top_subnet_share:
        return "Distributed /24 swarm"
    if swarmish_subnets >= 5:
        return "Subnet-focused swarm"
    if top_subnet_share >= 2.0:
        return "Broad subnet concentration"
    return "Broad low-intensity distribution"


def build_top_subnet_tables(analyzer, total_overall_requests, top_n):
    """Return top /24 views for markdown."""
    subnets = []
    for subnet_obj, metrics in analyzer.subnet_metrics.items():
        subnets.append({
            "target": str(subnet_obj),
            "requests": int(metrics.get("total_requests", 0) or 0),
            "ips": int(metrics.get("ip_count", 0) or 0),
            "rpm": float(metrics.get("subnet_req_per_min_window", 0.0) or 0.0),
            "time_span": float(metrics.get("subnet_time_span", 0.0) or 0.0),
            "share": pct(metrics.get("total_requests", 0), total_overall_requests),
        })

    top_by_requests = sorted(subnets, key=lambda x: x["requests"], reverse=True)[:top_n]
    top_by_ips = sorted(subnets, key=lambda x: (x["ips"], x["requests"]), reverse=True)[:top_n]
    return top_by_requests, top_by_ips


def build_top_supernet_table(analyzer, total_overall_requests, top_n):
    """Return top /16 table for markdown."""
    threat_like = []
    for subnet_obj, metrics in analyzer.subnet_metrics.items():
        row = metrics.copy()
        row["id"] = subnet_obj
        threat_like.append(row)
    supernets = []
    for supernet, metrics in aggregate_ipv4_supernet_pressure(threat_like).items():
        supernets.append({
            "target": str(supernet),
            "requests": metrics["total_requests"],
            "ips": metrics["total_ips"],
            "active_subnets": metrics["active_subnets"],
            "rpm": metrics["total_rpm"],
            "time_span": metrics["max_subnet_time_span"],
            "share": pct(metrics["total_requests"], total_overall_requests),
        })
    return sorted(supernets, key=lambda x: x["requests"], reverse=True)[:top_n]


def render_table(headers, rows):
    """Render a simple markdown table."""
    lines = []
    lines.append("| " + " | ".join(headers) + " |")
    lines.append("|" + "|".join(["---"] * len(headers)) + "|")
    for row in rows:
        lines.append("| " + " | ".join(row) + " |")
    return lines


def build_markdown(args, start_date_utc, end_date_utc, analysis_duration_seconds,
                   analyzer, total_overall_requests, cpu_load_percent,
                   simulations, command_line):
    """Build the full markdown report."""
    baseline = simulations[0]
    base_cfg = baseline["config"]
    dominant_pattern = detect_dominant_pattern(analyzer, total_overall_requests)

    ip_request_values = [m["total_requests"] for m in analyzer.ip_metrics.values()]
    ip_rpm_values = [
        entry["req_per_min_window"]
        for entry in build_ip_pressure_metrics(analyzer.ip_metrics, analysis_duration_seconds)
    ]
    subnet_request_values = [m["total_requests"] for m in analyzer.subnet_metrics.values()]
    subnet_rpm_values = [m["subnet_req_per_min_window"] for m in analyzer.subnet_metrics.values()]
    subnet_ip_values = [m["ip_count"] for m in analyzer.subnet_metrics.values()]

    threat_like = []
    for subnet_obj, metrics in analyzer.subnet_metrics.items():
        row = metrics.copy()
        row["id"] = subnet_obj
        threat_like.append(row)
    supernet_pressure = aggregate_ipv4_supernet_pressure(threat_like)
    supernet_request_values = [m["total_requests"] for m in supernet_pressure.values()]
    supernet_ip_values = [m["total_ips"] for m in supernet_pressure.values()]

    percentiles_table = render_table(
        ["Metric", "p50", "p90", "p95", "p99", "max"],
        [
            [
                "Requests per IP",
                format_number(metric_percentiles(ip_request_values)["p50"]),
                format_number(metric_percentiles(ip_request_values)["p90"]),
                format_number(metric_percentiles(ip_request_values)["p95"]),
                format_number(metric_percentiles(ip_request_values)["p99"]),
                format_number(metric_percentiles(ip_request_values)["max"]),
            ],
            [
                "Req/min per IP",
                format_number(metric_percentiles(ip_rpm_values)["p50"]),
                format_number(metric_percentiles(ip_rpm_values)["p90"]),
                format_number(metric_percentiles(ip_rpm_values)["p95"]),
                format_number(metric_percentiles(ip_rpm_values)["p99"]),
                format_number(metric_percentiles(ip_rpm_values)["max"]),
            ],
            [
                "Requests per /24",
                format_number(metric_percentiles(subnet_request_values)["p50"]),
                format_number(metric_percentiles(subnet_request_values)["p90"]),
                format_number(metric_percentiles(subnet_request_values)["p95"]),
                format_number(metric_percentiles(subnet_request_values)["p99"]),
                format_number(metric_percentiles(subnet_request_values)["max"]),
            ],
            [
                "Req/min per /24",
                format_number(metric_percentiles(subnet_rpm_values)["p50"]),
                format_number(metric_percentiles(subnet_rpm_values)["p90"]),
                format_number(metric_percentiles(subnet_rpm_values)["p95"]),
                format_number(metric_percentiles(subnet_rpm_values)["p99"]),
                format_number(metric_percentiles(subnet_rpm_values)["max"]),
            ],
            [
                "IP count per /24",
                format_number(metric_percentiles(subnet_ip_values)["p50"]),
                format_number(metric_percentiles(subnet_ip_values)["p90"]),
                format_number(metric_percentiles(subnet_ip_values)["p95"]),
                format_number(metric_percentiles(subnet_ip_values)["p99"]),
                format_number(metric_percentiles(subnet_ip_values)["max"]),
            ],
            [
                "Requests per /16",
                format_number(metric_percentiles(supernet_request_values)["p50"]),
                format_number(metric_percentiles(supernet_request_values)["p90"]),
                format_number(metric_percentiles(supernet_request_values)["p95"]),
                format_number(metric_percentiles(supernet_request_values)["p99"]),
                format_number(metric_percentiles(supernet_request_values)["max"]),
            ],
            [
                "IP count per /16",
                format_number(metric_percentiles(supernet_ip_values)["p50"]),
                format_number(metric_percentiles(supernet_ip_values)["p90"]),
                format_number(metric_percentiles(supernet_ip_values)["p95"]),
                format_number(metric_percentiles(supernet_ip_values)["p99"]),
                format_number(metric_percentiles(supernet_ip_values)["max"]),
            ],
        ]
    )

    top_subnets_by_requests, top_subnets_by_ips = build_top_subnet_tables(
        analyzer, total_overall_requests, args.top
    )
    top_supernets = build_top_supernet_table(analyzer, total_overall_requests, args.top)

    current_outcome_rows = [
        [
            "IP",
            str(len(baseline["blocked_ips"])),
            str(len(baseline["blocked_ips"])),
            str(sum(entry["total_requests"] for entry in baseline["blocked_ips"])),
            format_number(pct(sum(entry["total_requests"] for entry in baseline["blocked_ips"]), total_overall_requests)),
        ],
        [
            "/24",
            str(len(baseline["blocked_subnets_direct"])),
            str(len(baseline["blocked_subnets_direct"])),
            str(sum(entry["total_requests"] for entry in baseline["blocked_subnets_direct"])),
            format_number(pct(sum(entry["total_requests"] for entry in baseline["blocked_subnets_direct"]), total_overall_requests)),
        ],
        [
            "/16",
            str(len(baseline["blocked_supernets"])),
            str(len(baseline["blocked_supernets"])),
            str(sum(data["total_requests"] for _, data in baseline["blocked_supernets"])),
            format_number(pct(sum(data["total_requests"] for _, data in baseline["blocked_supernets"]), total_overall_requests)),
        ],
        [
            "Total (deduped estimate)",
            str(len(baseline["blocked_ips"]) + len(baseline["blocked_subnets_direct"]) + len(baseline["blocked_supernets"])),
            str(baseline["estimated_rules"]),
            str(baseline["covered_requests"]),
            format_number(baseline["coverage_percent"]),
        ],
    ]

    sensitivity_rows = []
    for simulation in simulations:
        profile_label = simulation["profile_label"]
        profile_cfg = simulation["config"]
        notes = "Stable default"
        if "Conservative" in profile_label:
            notes = "Safer, lower sensitivity"
        elif "Aggressive" in profile_label:
            notes = "Higher false-positive risk"
        elif profile_label == "Balanced B":
            notes = "Better swarm capture"
        sensitivity_rows.append([
            profile_label,
            describe_profile_changes(base_cfg, profile_cfg),
            str(len(simulation["blocked_ips"])),
            str(len(simulation["blocked_subnets_direct"])),
            str(len(simulation["blocked_supernets"])),
            format_number(simulation["coverage_percent"]),
            str(simulation["estimated_rules"]),
            notes,
        ])

    subnet_near = classify_subnet_near_misses(baseline, analysis_duration_seconds)
    supernet_near = classify_supernet_near_misses(baseline, analysis_duration_seconds, cpu_load_percent)
    ip_near = classify_ip_near_misses(baseline, analyzer, analysis_duration_seconds)

    top_subnet_rows = render_table(
        ["/24", "Requests", "IPs", "Req/min", "TimeSpan(s)", "Share %"],
        [
            [
                row["target"],
                str(row["requests"]),
                str(row["ips"]),
                format_number(row["rpm"]),
                format_number(row["time_span"]),
                format_number(row["share"]),
            ]
            for row in top_subnets_by_requests
        ]
    )

    top_ipcount_rows = render_table(
        ["/24", "Requests", "IPs", "Req/min", "TimeSpan(s)"],
        [
            [
                row["target"],
                str(row["requests"]),
                str(row["ips"]),
                format_number(row["rpm"]),
                format_number(row["time_span"]),
            ]
            for row in top_subnets_by_ips
        ]
    )

    top_supernet_rows = render_table(
        ["/16", "Requests", "IPs", "Active /24", "Req/min", "Max Subnet Span(s)", "Share %"],
        [
            [
                row["target"],
                str(row["requests"]),
                str(row["ips"]),
                str(row["active_subnets"]),
                format_number(row["rpm"]),
                format_number(row["time_span"]),
                format_number(row["share"]),
            ]
            for row in top_supernets
        ]
    )

    lines = []
    lines.append("# Tuning Snapshot")
    lines.append("")
    lines.append("## Executive Summary")
    lines.append(f"- Window: `{start_date_utc.isoformat()}` to `{end_date_utc.isoformat()}`")
    lines.append(f"- Duration: `{int(analysis_duration_seconds)}s`")
    lines.append(f"- Total requests: `{total_overall_requests}`")
    lines.append(f"- Unique IPs: `{len(analyzer.ip_metrics)}`")
    lines.append(f"- Unique /24: `{len(analyzer.subnet_metrics)}`")
    lines.append(f"- Unique /16: `{len(supernet_pressure)}`")
    lines.append(
        f"- Global req/min: `{format_number((total_overall_requests / (analysis_duration_seconds / 60.0)) if analysis_duration_seconds > 0 else 0.0)}`"
    )
    lines.append(f"- Host load (1m normalized): `{format_number(cpu_load_percent)}%`")
    lines.append(f"- Dominant pattern: `{dominant_pattern}`")
    lines.append(f"- Baseline preset: `{base_cfg.baseline_preset}`")
    lines.append(f"- Baseline source chain: `{base_cfg.baseline_source_chain}`")
    lines.append(
        f"- Current config effect: `{len(baseline['blocked_subnets_direct'])} /24, "
        f"{len(baseline['blocked_supernets'])} /16, {len(baseline['blocked_ips'])} IP, "
        f"{format_number(baseline['coverage_percent'])}% estimated coverage`"
    )
    subnet_main_constraint = max(subnet_near.items(), key=lambda item: item[1])[0] if subnet_near else "N/A"
    lines.append(f"- Main limiting condition: `{subnet_main_constraint}`")
    lines.append("")
    lines.append("## Window Summary")
    lines.extend(render_table(
        ["Metric", "Value"],
        [
            ["Total requests", str(total_overall_requests)],
            ["Unique IPs", str(len(analyzer.ip_metrics))],
            ["Unique /24", str(len(analyzer.subnet_metrics))],
            ["Unique /16", str(len(supernet_pressure))],
            ["Global req/min", format_number((total_overall_requests / (analysis_duration_seconds / 60.0)) if analysis_duration_seconds > 0 else 0.0)],
            ["Host load 1m normalized", f"{format_number(cpu_load_percent)}%"],
            ["Effective /24 RPM threshold", format_number(baseline["effective_rpm_threshold"])],
            ["Effective /24 sustained threshold", f"{format_number(baseline['effective_sustained_percent'])}%"],
            ["Effective IP RPM threshold", format_number(baseline["effective_ip_rpm_threshold"])],
            ["Effective IP sustained threshold", f"{format_number(baseline['effective_ip_sustained_percent'])}%"],
        ]
    ))
    lines.append("")
    lines.append("## Traffic Shape")
    lines.append("")
    lines.append("### Percentiles")
    lines.extend(percentiles_table)
    lines.append("")
    lines.append("### Top /24 by Requests")
    lines.extend(top_subnet_rows)
    lines.append("")
    lines.append("### Top /24 by IP Count")
    lines.extend(top_ipcount_rows)
    lines.append("")
    lines.append("### Top /16 by Aggregated Pressure")
    lines.extend(top_supernet_rows)
    lines.append("")
    lines.append("## Current Config Outcome")
    lines.append("")
    lines.append("### Current Parameters")
    lines.append(f"- `baseline-preset: {base_cfg.baseline_preset}`")
    lines.append(f"- `baseline-source-chain: {base_cfg.baseline_source_chain}`")
    lines.append(f"- `min-rpm-threshold: {format_number(base_cfg.min_rpm_threshold)}`")
    lines.append(f"- `min-sustained-percent: {format_number(base_cfg.min_sustained_percent)}`")
    lines.append(f"- `max-cpu-load-threshold: {format_number(base_cfg.max_cpu_load_threshold)}`")
    lines.append(f"- `ip-swarm-threshold: {base_cfg.ip_swarm_threshold}`")
    lines.append(f"- `ip-swarm-rpm-factor: {format_number(base_cfg.ip_swarm_rpm_factor)}`")
    lines.append(f"- `ip-swarm-bonus-max: {format_number(base_cfg.ip_swarm_bonus_max)}`")
    lines.append(f"- `ip-min-rpm-threshold: {format_number(base_cfg.ip_min_rpm_threshold)}`")
    lines.append(f"- `ip-min-sustained-percent: {format_number(base_cfg.ip_min_sustained_percent)}`")
    lines.append(f"- `ip-min-requests: {base_cfg.ip_min_requests}`")
    lines.append(f"- `supernet-min-rpm-total: {format_number(base_cfg.supernet_min_rpm_total)}`")
    lines.append(f"- `supernet-min-ip-count: {base_cfg.supernet_min_ip_count}`")
    lines.append(f"- `supernet-min-requests: {base_cfg.supernet_min_requests}`")
    lines.append("")
    lines.append("### Simulated Outcome")
    lines.extend(render_table(
        ["Layer", "Targets blocked", "Estimated rules", "Requests covered", "Coverage %"],
        current_outcome_rows
    ))
    lines.append("")
    lines.append("### Interpretation")
    if len(baseline["blocked_supernets"]) > len(baseline["blocked_subnets_direct"]):
        lines.append("- Current settings favor `/16` containment over `/24` precision.")
    else:
        lines.append("- Current settings favor `/24` precision over `/16` aggregation.")
    if cpu_load_percent < base_cfg.max_cpu_load_threshold:
        lines.append(
            f"- `/16` layer is currently inactive because CPU load is below the `{format_number(base_cfg.max_cpu_load_threshold)}%` trigger."
        )
    if len(baseline["blocked_ips"]) == 0:
        lines.append("- IP-layer remains strict enough to avoid reacting to isolated bursts.")
    else:
        lines.append("- IP-layer is active and catching persistent single-IP outliers.")
    lines.append("")
    lines.append("## Near Miss Analysis")
    lines.append("")
    lines.append("### /24 Near Misses")
    lines.extend(render_table(
        ["Failure mode", "Count"],
        [[name, str(count)] for name, count in subnet_near.items()]
    ))
    lines.append("")
    lines.append("### /16 Near Misses")
    lines.extend(render_table(
        ["Failure mode", "Count"],
        [[name, str(count)] for name, count in supernet_near.items()]
    ))
    lines.append("")
    lines.append("### IP Near Misses")
    lines.extend(render_table(
        ["Failure mode", "Count"],
        [[name, str(count)] for name, count in ip_near.items()]
    ))
    lines.append("")
    lines.append("### Primary Constraints")
    lines.append(f"- `/24`: main blocker is `{max(subnet_near.items(), key=lambda item: item[1])[0]}`")
    if cpu_load_percent < base_cfg.max_cpu_load_threshold:
        lines.append("- `/16`: layer inactive in this window (CPU below trigger).")
    else:
        lines.append(f"- `/16`: main blocker is `{max(supernet_near.items(), key=lambda item: item[1])[0]}`")
    lines.append(f"- `IP`: main blocker is `{max(ip_near.items(), key=lambda item: item[1])[0]}`")
    lines.append("")
    lines.append("## Sensitivity Sweep")
    lines.extend(render_table(
        ["Profile", "Key changes", "IP blocks", "/24 blocks", "/16 blocks", "Coverage %", "Rule growth", "Notes"],
        sensitivity_rows
    ))
    lines.append("")
    lines.append("## Recommended Tuning Direction")
    lines.append("")
    lines.append("### Lower False Positives")
    lines.append("- Keep `ip-min-*` as-is.")
    lines.append("- Prefer reducing `/16` strictness before lowering `/24` RPM if the main goal is broader swarm capture.")
    lines.append("- Expected effect: better distributed capture with limited rule growth.")
    lines.append("")
    lines.append("### Higher Containment")
    lines.append(
        f"- Lower `min-rpm-threshold` from `{format_number(base_cfg.min_rpm_threshold)}` "
        f"toward `{format_number(max(0.5, base_cfg.min_rpm_threshold - 1.0))}`."
    )
    lines.append(
        f"- Lower `ip-swarm-threshold` from `{base_cfg.ip_swarm_threshold}` "
        f"toward `{max(2, base_cfg.ip_swarm_threshold - 10)}`."
    )
    lines.append(
        f"- Lower `supernet-min-ip-count` from `{base_cfg.supernet_min_ip_count}` "
        f"toward `{max(1, int(math.floor(base_cfg.supernet_min_ip_count * 0.90)))}`."
    )
    lines.append("- Expected effect: stronger swarm detection, more `/24` blocks, higher collateral risk.")
    lines.append("")
    lines.append("## Operational Cautions")
    lines.append("- Lowering `/24` RPM has the largest impact on rule count.")
    lines.append("- Lowering `ip-min-requests` increases single-IP sensitivity and false-positive risk.")
    lines.append("- `/16` changes can increase collateral impact faster than `/24` changes.")
    lines.append("- Validate aggressive profiles with blocker `--dry-run` before production.")
    lines.append("")
    lines.append("## Script Parameters")
    lines.extend(render_table(
        ["Parameter", "Value"],
        [
            ["`--file`", f"`{args.file}`"],
            ["`--time-window`", f"`{args.time_window if args.time_window else 'None'}`"],
            ["`--start-date`", f"`{args.start_date}`"],
            ["`--output`", f"`{args.output}`"],
            ["`--top`", f"`{args.top}`"],
            ["`--profile-set`", f"`{args.profile_set}`"],
            ["`--baseline-preset`", f"`{args.baseline_preset}`"],
            ["`--cron-file`", f"`{args.cron_file}`"],
            ["`--cron-command`", f"`{args.cron_command}`"],
            ["`--execution-log`", f"`{args.execution_log}`"],
            ["`baseline label`", f"`{base_cfg.baseline_label}`"],
            ["`baseline source chain`", f"`{base_cfg.baseline_source_chain}`"],
        ]
    ))
    lines.append("")
    lines.append("## How To Use These Parameters")
    lines.append("- `--time-window`: analyze a recent fixed window (`hour`, `6hour`, `day`, `week`).")
    lines.append("- `--start-date`: analyze from a specific point in time instead of a preset window.")
    lines.append("- `--top`: control how many top examples appear in each \"Top\" table.")
    lines.append("- `--profile-set`: choose the sweep size (`default`, `conservative`, `aggressive`, `extended`).")
    lines.append("- `--baseline-preset`: choose which internal blocker baseline the report simulates.")
    lines.append("- `--cron-file` / `--cron-command`: derive blocker thresholds from a cron entry.")
    lines.append("- If no cron source is passed, the script tries `crontab -l` for the current user.")
    lines.append("- If cron redirects stdout to a log file, that log is used automatically as the execution-log source.")
    lines.append("- `--execution-log`: explicitly override the auto-detected log and use its latest `PARAMS` line.")
    lines.append("")
    lines.append("### How To Interpret The Output")
    lines.append("- If most near-misses fail only by RPM, lower RPM thresholds first.")
    lines.append("- If most `/16` near-misses fail only by IP count, lower `supernet-min-ip-count`.")
    lines.append("- If IP near-misses fail mostly by request count, do not lower `ip-min-rpm-threshold` first.")
    lines.append("- If aggressive profiles sharply increase rule growth, prefer `/16` tuning before `/24` tuning.")
    lines.append("")
    lines.append("### Suggested Workflow")
    lines.append("1. Run the snapshot on the last hour.")
    lines.append("2. Read `Near Miss Analysis` before changing anything.")
    lines.append("3. Compare `Balanced` vs `Aggressive` profiles.")
    lines.append("4. Apply one small change at a time.")
    lines.append("5. Validate with blocker `--dry-run`.")
    lines.append("")
    lines.append("## Reproduce This Report")
    lines.append(f"`{command_line}`")
    lines.append("")
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(
        description="Generate a Markdown tuning snapshot for blocker parameter analysis.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument(
        "--file", "-f", default=DEFAULT_ACCESS_LOG,
        help="Path to the log file to analyze."
    )
    parser.add_argument(
        "--time-window", "-tw", default=None, choices=["hour", "6hour", "day", "week"],
        help="Recent window to analyze. Defaults to 'hour' when --start-date is not provided."
    )
    parser.add_argument(
        "--start-date", "-s", default=None,
        help="Manual start date (dd/Mmm/YYYY:HH:MM:SS). Used when --time-window is not set."
    )
    parser.add_argument("--whitelist", "-w", help="Whitelist file with IPs/subnets to exclude.")
    parser.add_argument("--output", "-o", default="tuning-snapshot.md", help="Markdown output file.")
    parser.add_argument("--top", "-n", type=int, default=5, help="Number of top examples per table.")
    parser.add_argument(
        "--profile-set", choices=["default", "conservative", "aggressive", "extended"],
        default="default", help="Sensitivity sweep size."
    )
    parser.add_argument(
        "--log-level", choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
        default="INFO", help="Console logging level."
    )
    parser.add_argument(
        "--baseline-preset",
        choices=sorted(BASELINE_PRESETS.keys()),
        default="lareferencia-hourly",
        help="Named blocker baseline to simulate."
    )
    parser.add_argument(
        "--cron-file",
        default=None,
        help="Optional cron file to inspect for a blocker.py command."
    )
    parser.add_argument(
        "--cron-command",
        default=None,
        help="Optional literal cron command line to inspect."
    )
    parser.add_argument(
        "--execution-log",
        default=None,
        help="Optional blocker execution log; overrides auto-detected cron log and latest PARAMS line overrides cron/preset values."
    )

    args = parser.parse_args()
    base_cfg, source_time_window, resolved_execution_log = build_config_from_sources(args)
    if not args.execution_log and resolved_execution_log:
        args.execution_log = resolved_execution_log
    if args.time_window is None and not args.start_date:
        if source_time_window in ("hour", "6hour", "day", "week"):
            args.time_window = source_time_window
        else:
            args.time_window = "hour"

    setup_logging(args.log_level)
    logger = logging.getLogger("tuning_snapshot")

    if not os.path.exists(args.file):
        logger.error("Log file not found: %s", args.file)
        sys.exit(1)

    now_utc = datetime.now(timezone.utc)
    start_date_utc = None
    if args.time_window:
        start_local = calculate_start_date(args.time_window)
        start_date_utc = start_local.astimezone().astimezone(timezone.utc)
    elif args.start_date:
        try:
            parsed_local = datetime.strptime(args.start_date, "%d/%b/%Y:%H:%M:%S")
            start_date_utc = parsed_local.astimezone().astimezone(timezone.utc)
        except ValueError:
            logger.error("Invalid --start-date format. Use dd/Mmm/YYYY:HH:MM:SS.")
            sys.exit(1)

    if start_date_utc is None:
        logger.error("Could not determine analysis start date.")
        sys.exit(1)

    analysis_duration_seconds = max(0.0, (now_utc - start_date_utc).total_seconds())

    analyzer = ThreatAnalyzer()
    if args.whitelist:
        analyzer.load_whitelist_from_file(args.whitelist)

    total_overall_requests = analyzer.analyze_log_file(args.file, start_date_utc=start_date_utc)
    if total_overall_requests < 0:
        logger.error("Log analysis failed.")
        sys.exit(1)
    if total_overall_requests == 0:
        logger.error("No valid entries found in the selected window.")
        sys.exit(1)

    if not analyzer._aggregate_subnet_metrics(analysis_duration_seconds=analysis_duration_seconds):
        logger.error("Subnet aggregation failed.")
        sys.exit(1)

    cpu_load_percent = get_normalized_cpu_load_percent()
    simulations = evaluate_profiles(
        analyzer=analyzer,
        analysis_duration_seconds=analysis_duration_seconds,
        cpu_load_percent=cpu_load_percent,
        total_overall_requests=total_overall_requests,
        profiles=build_profile_set(base_cfg, args.profile_set)
    )

    command_line = " ".join([sys.executable] + sys.argv)
    markdown = build_markdown(
        args=args,
        start_date_utc=start_date_utc,
        end_date_utc=now_utc,
        analysis_duration_seconds=analysis_duration_seconds,
        analyzer=analyzer,
        total_overall_requests=total_overall_requests,
        cpu_load_percent=cpu_load_percent,
        simulations=simulations,
        command_line=command_line
    )

    with open(args.output, "w", encoding="utf-8") as handle:
        handle.write(markdown)

    print(f"Markdown snapshot written to {args.output}")


if __name__ == "__main__":
    main()
