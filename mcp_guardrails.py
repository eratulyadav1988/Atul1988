import json
from typing import Dict, Any, List, Callable, Optional
from pydantic import BaseModel, Field

# 1. Define the Guardrail Schema
class GuardrailResult(BaseModel):
    is_safe: bool = Field(description="True if the tool call passes all security policies.")
    reason: Optional[str] = Field(default=None, description="Reason for failure if unsafe.")
    modified_arguments: Optional[Dict[str, Any]] = Field(default=None, description="Sanitized arguments if fixable.")

# 2. Core Guardrail Engine
class MCPGuardrailEngine:
    def __init__(self):
        # Sensitive commands or keywords to block in tool inputs
        self.blocked_patterns = [";", "&&", "||", "rm -rf", "sudo", "env", "credentials"]
        # Restricted directories for file operations
        self.allowed_directories = ["/safe_zone/", "./data/"]

    def verify_tool_call(self, tool_name: str, arguments: Dict[str, Any]) -> GuardrailResult:
        """
        Inspects MCP tool calls before they are dispatched to the MCP Server.
        """
        # Rule 1: Prevent Command Injection in shell/execution tools
        if tool_name in ["run_command", "execute_bash", "ssh_cmd"]:
            command = arguments.get("command", "")
            for pattern in self.blocked_patterns:
                if pattern in command:
                    return GuardrailResult(
                        is_safe=False, 
                        reason=f"Security Violation: Blocked pattern '{pattern}' detected in command."
                    )

        # Rule 2: Enforce Path Traversal Protection for file tools
        if tool_name in ["read_file", "write_file", "edit_file"]:
            path = arguments.get("path", "")
            # Block directory traversal attacks
            if ".." in path or path.startswith("/etc") or path.startswith("/var"):
                return GuardrailResult(
                    is_safe=False,
                    reason=f"Security Violation: Path traversal attempt or restricted area access: {path}"
                )
            
            # Optional: Ensure path stays within a safe sandbox directory
            if not any(path.startswith(allowed) for allowed in self.allowed_directories):
                return GuardrailResult(
                    is_safe=False,
                    reason=f"Policy Violation: Path must reside within allowed directories: {self.allowed_directories}"
                )

        # Rule 3: Data Masking / PII Sanitization (Modifying arguments on the fly)
        if "text" in arguments or "content" in arguments:
            key = "text" if "text" in arguments else "content"
            content = arguments[key]
            # Simple dummy check for mock PII (e.g., masking API Keys or Passwords)
            if "sk-" in content or "password=" in content:
                sanitized_content = content.replace("sk-", "[MASKED_API_KEY]")
                arguments[key] = sanitized_content
                return GuardrailResult(
                    is_safe=True,
                    reason="PII Masked successfully.",
                    modified_arguments=arguments
                )

        # Passes all checks
        return GuardrailResult(is_safe=True)

# 3. Agent Interceptor Wrapper
class SafeMCPAgentWrapper:
    def __init__(self, mcp_client: Any, guardrail_engine: MCPGuardrailEngine):
        self.mcp_client = mcp_client
        self.guardrails = guardrail_engine

    def execute_agent_tool(self, tool_name: str, arguments: Dict[str, Any]) -> Any:
        """
        The wrapper method your Agent calls instead of hitting the MCP client directly.
        """
        print(f"\n[Guardrail Log] Inspecting tool call: '{tool_name}'...")
        
        # Run checks
        check = self.guardrails.verify_tool_call(tool_name, arguments)
        
        if not check.is_safe:
            print(f"❌ [ALERT] Guardrail blocked execution! Reason: {check.reason}")
            # Instead of crashing, return a safe rejection message back to the LLM Agent
            return {
                "error": "Execution policy violation",
                "details": check.reason
            }
        
        # If arguments were modified/sanitized, use the safe version
        final_arguments = check.modified_arguments if check.modified_arguments else arguments
        if check.modified_arguments:
            print("⚠️ [Guardrail Log] Arguments sanitized before execution.")

        print("✅ [Guardrail Log] Tool call approved. Forwarding to MCP Server.")
        # Simulating the real MCP client dispatch call
        # return self.mcp_client.call_tool(name=tool_name, arguments=final_arguments)
        return {"status": "success", "message": "Executed successfully by MCP server"}

# --- 4. Simulation / Testing ---
if __name__ == "__main__":
    # Initialize Engine and Wrapper
    engine = MCPGuardrailEngine()
    # Passing None as a mock MCP client for demonstration
    safe_agent = SafeMCPAgentWrapper(mcp_client=None, guardrail_engine=engine)

    # Test Case 1: Safe File Read Request
    safe_agent.execute_agent_tool(
        tool_name="read_file", 
        arguments={"path": "./data/config.json"}
    )

    # Test Case 2: Exploit Attempt (Path Traversal to system files)
    safe_agent.execute_agent_tool(
        tool_name="read_file", 
        arguments={"path": "../../etc/passwd"}
    )

    # Test Case 3: Exploit Attempt (Command Injection via MCP tool)
    safe_agent.execute_agent_tool(
        tool_name="run_command", 
        arguments={"command": "echo 'Hello'; rm -rf /"}
    )

    # Test Case 4: PII leakage mitigation
    safe_agent.execute_agent_tool(
        tool_name="write_file", 
        arguments={"path": "./data/log.txt", "content": "My secret key is sk-12345abc"}
    )
