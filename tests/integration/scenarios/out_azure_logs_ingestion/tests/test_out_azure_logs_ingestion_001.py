import logging
import math
import os
import re
import shutil
import tempfile
import time

import requests

from server.http_server import (
    configure_http_response,
    configure_oauth_token_response,
    data_storage,
    http_server_run,
)
from utils.test_service import FluentBitTestService

logger = logging.getLogger(__name__)


class Service:
    def __init__(self, config_file):
        self.config_file = os.path.abspath(os.path.join(os.path.dirname(__file__), "../config", config_file))
        cert_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../in_splunk/certificate"))
        self.tls_crt_file = os.path.join(cert_dir, "certificate.pem")
        self.tls_key_file = os.path.join(cert_dir, "private_key.pem")
        self.store_dir = tempfile.mkdtemp(prefix="fluent-bit-azure-logs-ingestion-")
        self.oauth_server_port = None
        self.service = FluentBitTestService(
            self.config_file,
            data_storage=data_storage,
            data_keys=["payloads", "requests"],
            extra_env={
                "CERTIFICATE_TEST": self.tls_crt_file,
                "PRIVATE_KEY_TEST": self.tls_key_file,
                "AZURE_LOGS_INGESTION_STORE_DIR": self.store_dir,
            },
            pre_start=self._start_receiver,
            post_stop=self._stop_receiver,
        )

    def _start_receiver(self, service):
        self.oauth_server_port = service.allocate_port_env("TEST_SUITE_OAUTH_PORT")
        http_server_run(self.oauth_server_port)
        http_server_run(
            service.test_suite_http_port,
            use_tls=True,
            tls_crt_file=self.tls_crt_file,
            tls_key_file=self.tls_key_file,
            reset_state=False,
        )

        def _http_ready():
            try:
                response = requests.get(
                    f"http://127.0.0.1:{self.oauth_server_port}/ping",
                    timeout=1,
                )
                return response.status_code == 200
            except requests.RequestException:
                return False

        def _https_ready():
            try:
                response = requests.get(
                    f"https://localhost:{service.test_suite_http_port}/ping",
                    timeout=1,
                    verify=self.tls_crt_file,
                )
                return response.status_code == 200
            except requests.RequestException:
                return False

        self.service.wait_for_condition(
            _http_ready,
            timeout=10,
            interval=0.5,
            description="azure logs ingestion oauth receiver readiness",
        )

        self.service.wait_for_condition(
            _https_ready,
            timeout=10,
            interval=0.5,
            description="azure logs ingestion receiver readiness",
        )

    def _stop_receiver(self, service):
        try:
            if self.oauth_server_port is not None:
                requests.post(
                    f"http://127.0.0.1:{self.oauth_server_port}/shutdown",
                    timeout=2,
                )
        except requests.RequestException:
            pass

        try:
            requests.post(
                f"https://localhost:{service.test_suite_http_port}/shutdown",
                timeout=2,
                verify=self.tls_crt_file,
            )
        except requests.RequestException:
            pass

        shutil.rmtree(self.store_dir, ignore_errors=True)

    def start(self):
        self.service.start()
        self.flb = self.service.flb
        self.flb_listener_port = self.service.flb_listener_port
        self.test_suite_http_port = self.service.test_suite_http_port

    def stop(self):
        self.service.stop()

    def wait_for_requests(self, minimum_count, timeout=10):
        return self.service.wait_for_condition(
            lambda: data_storage["requests"] if len(data_storage["requests"]) >= minimum_count else None,
            timeout=timeout,
            interval=0.5,
            description=f"{minimum_count} azure logs ingestion requests",
        )

    def data_requests(self):
        return [
            request
            for request in data_storage["requests"]
            if request["path"] == "/dataCollectionRules/dcr-suite/streams/Custom-suite_CL"
        ]

    def batch_preparations(self):
        with open(self.service.flb.log_file, "r", encoding="utf-8") as log_file:
            matches = re.findall(
                r"prepared buffered batch records=(\d+) bytes=(\d+) "
                r"gzip_operations=(\d+)",
                log_file.read(),
            )

        return [
            {
                "records": int(record_count),
                "bytes": int(request_size),
                "gzip_operations": int(gzip_operations),
            }
            for record_count, request_size, gzip_operations in matches
        ]

    def send_log(self, message):
        response = requests.post(
            f"http://127.0.0.1:{self.flb_listener_port}/azure_logs_ingestion",
            json={"message": message},
            timeout=5,
        )
        response.raise_for_status()


def test_out_azure_logs_ingestion_legacy_oauth2_and_payload_format():
    service = Service("out_azure_logs_ingestion_oauth2.yaml")
    service.start()
    configure_http_response(status_code=200, body={"status": "received"})
    configure_oauth_token_response(
        status_code=200,
        body={"access_token": "oauth-access-token", "token_type": "Bearer", "expires_in": 300},
    )

    requests_seen = service.wait_for_requests(2, timeout=15)
    service.stop()

    token_request = next(request for request in requests_seen if request["path"] == "/oauth/token")
    data_request = next(
        request
        for request in requests_seen
        if request["path"] == "/dataCollectionRules/dcr-suite/streams/Custom-suite_CL"
    )

    assert token_request["method"] == "POST"
    assert "grant_type=client_credentials" in token_request["raw_data"]
    assert "scope=https://monitor.azure.com/.default" in token_request["raw_data"]
    assert "client_id=suite-client" in token_request["raw_data"]
    assert "client_secret=suite-secret" in token_request["raw_data"]

    assert data_request["method"] == "POST"
    assert data_request["query_string"] == "api-version=2021-11-01-preview"
    assert data_request["headers"].get("Authorization") == "Bearer oauth-access-token"
    assert data_request["headers"].get("Content-Encoding") == "gzip"
    assert data_request["headers"].get("Content-Type") == "application/json"

    payload = data_request["json"]
    assert isinstance(payload, list)
    assert len(payload) == 1
    assert payload[0]["message"] == "hello from azure logs ingestion"
    assert payload[0]["source"] == "dummy"
    assert payload[0]["level"] == "info"
    assert isinstance(payload[0]["@timestamp"], (int, float))


def test_out_azure_logs_ingestion_batches_by_compressed_size_and_timeout():
    service = Service("out_azure_logs_ingestion_batching.yaml")
    service.start()
    configure_http_response(status_code=200, body={"status": "received"})
    configure_oauth_token_response(
        status_code=200,
        body={"access_token": "oauth-access-token", "token_type": "Bearer", "expires_in": 300},
    )

    service.service.wait_for_http_endpoint(
        f"http://127.0.0.1:{service.flb_listener_port}/health",
        timeout=10,
        interval=0.25,
    )

    messages = ["underfilled"]
    messages.extend(
        f"{index:02d}-"
        "4f2f8db8-e337-4d2f-9cb2-17008f6de8ce-"
        "ab8cc998-1ed2-46df-8728-b87681522731-"
        f"{index * 7919:08x}"
        for index in range(30)
    )

    service.send_log(messages[0])
    time.sleep(1.5)
    assert service.data_requests() == []

    for message in messages[1:]:
        service.send_log(message)

    first_batch = service.service.wait_for_condition(
        lambda: service.data_requests()[0] if service.data_requests() else None,
        timeout=10,
        interval=0.25,
        description="a compressed-size Azure Logs Ingestion batch",
    )

    assert 1 < len(first_batch["json"]) < len(messages)
    assert first_batch["headers"].get("Content-Encoding") == "gzip"
    assert 122 <= int(first_batch["headers"]["Content-Length"]) <= 175

    service.service.wait_for_condition(
        lambda: service.data_requests()
        if sum(len(request["json"]) for request in service.data_requests()) == len(messages)
        else None,
        timeout=10,
        interval=0.25,
        description="the full Azure Logs Ingestion batches",
    )

    request_count = len(service.data_requests())
    timeout_message = "timeout-partial-batch"
    service.send_log(timeout_message)
    time.sleep(1.5)
    assert len(service.data_requests()) == request_count

    requests_seen = service.service.wait_for_condition(
        lambda: service.data_requests()
        if sum(len(request["json"]) for request in service.data_requests()) ==
        len(messages) + 1
        else None,
        timeout=10,
        interval=0.25,
        description="the timed-out partial Azure Logs Ingestion batch",
    )

    observed_ratios = [
        len(request["decoded_data"].encode("utf-8")) /
        int(request["headers"]["Content-Length"])
        for request in requests_seen
    ]
    expected_ratio = observed_ratios[0]
    for observed_ratio in observed_ratios[1:]:
        expected_ratio = expected_ratio * 0.75 + observed_ratio * 0.25

    def compression_ratio_metric():
        response = requests.get(
            f"http://127.0.0.1:{service.flb.http_monitoring_port}"
            "/api/v2/metrics/prometheus",
            timeout=5,
        )
        response.raise_for_status()
        match = re.search(
            r'fluentbit_azure_logs_ingestion_compression_ratio'
            r'\{[^}]*name="azure_logs_ingestion\.0"[^}]*\}\s+([0-9.eE+-]+)',
            response.text,
        )
        if match is None:
            return None

        ratio = float(match.group(1))
        return ratio if math.isclose(ratio, expected_ratio, rel_tol=1e-6) else None

    compression_ratio = service.service.wait_for_condition(
        compression_ratio_metric,
        timeout=5,
        interval=0.25,
        description="the Azure Logs Ingestion compression ratio metric",
    )
    assert compression_ratio > 1

    batch_preparations = service.batch_preparations()
    service.stop()

    full_batches = [
        preparation
        for preparation in batch_preparations
        if preparation["bytes"] >= 122
    ]
    assert len(full_batches) >= 3
    assert all(preparation["bytes"] <= 175 for preparation in full_batches)
    assert 130 <= (
        sum(preparation["bytes"] for preparation in full_batches) /
        len(full_batches)
    ) <= 166
    assert (
        sum(preparation["gzip_operations"] for preparation in full_batches) /
        len(full_batches)
    ) < 2
    assert len(batch_preparations) == len(requests_seen)
    assert batch_preparations[-1]["bytes"] < 122
    assert batch_preparations[-1]["records"] == 1

    received_messages = [
        record["message"]
        for request in requests_seen
        for record in request["json"]
    ]
    assert received_messages == messages + [timeout_message]
