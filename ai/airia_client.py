import json
import os

import requests


class AiriaClient:
    """
    Client for sending ThreatLens security alerts
    to the Airia AI analysis pipeline.
    """

    API_URL = os.getenv("AIRIA_API_URL")

    def __init__(self, timeout=60):
        self.api_key = os.getenv("AIRIA_API_KEY")
        self.timeout = timeout

        if not self.api_key:
            raise RuntimeError(
                "AIRIA_API_KEY environment variable is not set"
            )

    def analyze(self, alert):
        """
        Send a ThreatLens alert to Airia and return
        the structured AI enrichment.
        """

        payload = {
            "userInput": json.dumps(alert),
            "asyncOutput": False
        }

        headers = {
            "X-API-KEY": self.api_key,
            "Content-Type": "application/json"
        }

        response = requests.post(
            self.API_URL,
            headers=headers,
            json=payload,
            timeout=self.timeout
        )

        response.raise_for_status()

        data = response.json()

        result = data.get("result")

        if not result:
            raise ValueError("Airia returned an empty result")

        # Airia returns the structured model output
        # as a JSON string inside "result".
        if isinstance(result, str):
            result = json.loads(result)

        if not isinstance(result, dict):
            raise ValueError("Unexpected Airia result format")

        return result