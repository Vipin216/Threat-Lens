from detection.detection_context import DetectionContext
from detection.detection_result import DetectionResult


class DetectionEngine:

    def detect(self, context: DetectionContext) -> list[DetectionResult]:

        results = []

        for source_ip in context.get_all_sources():

            vectors = context.get_source_vectors(
                source_ip
            )

            result = self._analyze_source(
                source_ip,
                vectors,
            )

            if result.detected:
                results.append(result)

        return results

    def _analyze_source(self, source_ip, vectors) -> DetectionResult:

        score = 0
        reasons = []

        if not vectors:
            return DetectionResult(
                detected=False,
                severity="NONE",
                score=0,
                source_ip=source_ip,
            )

        latest = vectors[-1]

        if latest.unique_destination_ports >= 10:
            score += 40
            reasons.append(
                "High number of unique destination ports"
            )

        if (
            latest.window_syn_ratio >= 0.7
            and latest.unique_destination_ports >= 5
        ):
            score += 25
            reasons.append(
                "High SYN ratio across multiple ports"
            )

        if (
            latest.syns_per_second >= 2
            and latest.window_syn_ratio >= 0.7
        ):
            score += 30
            reasons.append(
                "High SYN connection-attempt rate"
            )

        if (
            latest.syns_per_second >= 2
            and latest.window_syn_ratio >= 0.7
            and latest.unique_destination_ports >= 10
        ):
            score += 30
            reasons.append(
                "High-rate SYN activity across multiple ports"
            )

        if latest.sensitive_port_count > 0:
            score += 20
            reasons.append(
                f"Traffic to {latest.sensitive_port_count} sensitive port(s)"
            )

        if latest.sensitive_port_count >= 2:
            score += 20
            reasons.append(
                "Multiple sensitive services targeted"
            )

        if (
            latest.window_icmp_ratio >= 0.8
            and latest.window_icmp_request_ratio >= 0.7
            and latest.window_packets_per_second >= 2
        ):
            score += 50
            reasons.append(
                "High ICMP echo-request traffic rate"
            )

        score = min(score, 100)

        if score >= 70:
            severity = "HIGH"
        elif score >= 40:
            severity = "MEDIUM"
        elif score > 0:
            severity = "LOW"
        else:
            severity = "NONE"

        return DetectionResult(
            detected=score > 0,
            severity=severity,
            score=score,
            source_ip=source_ip,
            reasons=reasons,
        )