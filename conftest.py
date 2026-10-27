"""Authenticate the original tests' Flask transport without changing their assertions.

The original tests predate pairing. This fixture supplies a random bearer token
just as a paired extension does; the application always enforces authentication.
Tests for rejection explicitly send an empty/wrong Authorization header.
No detectors or analysis responses are mocked.
"""
import secrets
import pytest
from flask import Flask


@pytest.fixture(autouse=True)
def paired_test_transport(monkeypatch):
    token = secrets.token_urlsafe(32)
    monkeypatch.setenv('PHISHGUARD_API_TOKEN', token)
    original = Flask.test_client

    def paired_client(app, *args, **kwargs):
        client = original(app, *args, **kwargs)
        client.environ_base['HTTP_AUTHORIZATION'] = 'Bearer ' + token
        return client

    monkeypatch.setattr(Flask, 'test_client', paired_client)
