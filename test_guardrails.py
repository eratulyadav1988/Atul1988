import pytest
from mcp_guardrails import MCPGuardrailEngine

def test_safe_path():
    engine = MCPGuardrailEngine()
    result = engine.verify_tool_call("read_file", {"path": "./data/config.json"})
    assert result.is_safe == True

def test_path_traversal_blocked():
    engine = MCPGuardrailEngine()
    result = engine.verify_tool_call("read_file", {"path": "../../etc/passwd"})
    assert result.is_safe == False
    assert "Security Violation" in result.reason

def test_command_injection_blocked():
    engine = MCPGuardrailEngine()
    result = engine.verify_tool_call("run_command", {"command": "ls; rm -rf /"})
    assert result.is_safe == False

def test_pii_masking():
    engine = MCPGuardrailEngine()
    arguments = {"path": "./data/log.txt", "content": "api_key = sk-secure123"}
    result = engine.verify_tool_call("write_file", arguments)
    assert result.is_safe == True
    assert "[MASKED_API_KEY]" in result.modified_arguments["content"]
