from detection.detection_context import DetectionContext
from detection.detection_result import DetectionResult


class DetectionEngine:

    def detect(
        self,
        context: DetectionContext,
    ) -> list[DetectionResult]:

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

    def _analyze_source(
        self,
        source_ip,
        vectors,
    ) -> DetectionResult:

        score = 0
        reasons = []

        if not vectors:
            return DetectionResult(
                detected=False,
                severity="NONE",
                score=0,
                source_ip=source_ip,
                reasons=[],
            )

        # Use the latest feature vector for this source.
        latest = vectors[-1]

        # =====================================================
        # 1. SYN / PORT SCANNING
        # =====================================================

        # Many destination ports is suspicious only when
        # accompanied by SYN-heavy traffic.
        if (
            latest.unique_destination_ports >= 10
            and latest.window_syn_ratio >= 0.5
        ):
            score += 40
            reasons.append(
                "High number of unique destination ports"
            )

        # Strong SYN scanning indicator.
        if (
            latest.window_syn_ratio >= 0.7
            and latest.unique_destination_ports >= 5
        ):
            score += 25
            reasons.append(
                "High SYN ratio across multiple ports"
            )

        # High-rate SYN activity.
        if (
            latest.syns_per_second >= 2
            and latest.window_syn_ratio >= 0.7
        ):
            score += 30
            reasons.append(
                "High SYN connection-attempt rate"
            )

        # Very strong combination of high-rate SYNs
        # across many ports.
        if (
            latest.syns_per_second >= 2
            and latest.window_syn_ratio >= 0.7
            and latest.unique_destination_ports >= 10
        ):
            score += 30
            reasons.append(
                "High-rate SYN activity across multiple ports"
            )

        # =====================================================
        # 2. SENSITIVE PORT TARGETING
        # =====================================================

        # Sensitive ports alone should NOT automatically
        # indicate an attack.
        #
        # Only score this when there is stronger evidence
        # of scanning/SYN activity.
        if (
            latest.sensitive_port_count > 0
            and (
                latest.window_syn_ratio >= 0.7
                or latest.unique_destination_ports >= 5
            )
        ):
            score += 20
            reasons.append(
                f"Traffic to {latest.sensitive_port_count} "
                "sensitive port(s)"
            )

        if (
            latest.sensitive_port_count >= 2
            and latest.window_syn_ratio >= 0.7
        ):
            score += 20
            reasons.append(
                "Multiple sensitive services targeted"
            )

        # =====================================================
        # 3. HIGH TRAFFIC VOLUME
        # =====================================================

        # IMPORTANT:
        # High packet rate by itself is NOT an attack.
        #
        # Normal applications such as browsers can easily
        # generate >2 packets/sec.
        #
        # Therefore packet-rate scoring requires another
        # suspicious characteristic.

        if latest.window_packets_per_second >= 2:

            suspicious_pattern = (
                latest.window_syn_ratio >= 0.7
                or latest.window_icmp_request_ratio >= 0.8
                or latest.unique_destination_ports >= 10
            )

            if suspicious_pattern:
                score += 20
                reasons.append(
                    "High packet rate with suspicious traffic pattern"
                )

        # =====================================================
        # 4. ICMP FLOOD
        # =====================================================

        # High ICMP request ratio + high packet rate is
        # suspicious.
        if (
            latest.window_icmp_request_ratio >= 0.8
            and latest.window_packets_per_second >= 2
        ):
            score += 50
            reasons.append(
                "High ICMP echo-request traffic rate"
            )

        # =====================================================
        # FINAL SCORE
        # =====================================================

        score = min(score, 100)

        if score >= 70:
            severity = "HIGH"

        elif score >= 40:
            severity = "MEDIUM"

        elif score > 0:
            severity = "LOW"

        else:
            severity = "NONE"

        # A detection must have a meaningful suspicious
        # pattern. Normal traffic should not be detected
        # simply because it has a high packet rate.
        detected = score > 0



        return DetectionResult(
            detected=detected,
            severity=severity,
            score=score,
            source_ip=source_ip,
            reasons=reasons,
        )