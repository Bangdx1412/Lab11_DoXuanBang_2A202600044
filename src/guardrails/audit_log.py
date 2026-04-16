"""
Lab 11 — Audit Log Plugin
Captures interactions and exports them to JSON for monitoring.
"""
import json
import time
from datetime import datetime
from google.adk.plugins import base_plugin
from google.genai import types

class AuditLogPlugin(base_plugin.BasePlugin):
    """Plugin that records every interaction for security auditing.
    
    This records: input, output, latency, and status. It helps identify
    patterns of abuse and verify that guardrails are functioning correctly.
    """
    
    def __init__(self, log_file="audit_log.json"):
        super().__init__(name="audit_log")
        self.log_file = log_file
        self.logs = []
        self.active_requests = {} # session_id -> start_time

    async def on_user_message_callback(self, *, invocation_context, user_message):
        """Record the start of a request."""
        try:
            session_id = invocation_context.session.id if invocation_context and hasattr(invocation_context, 'session') and invocation_context.session else "unknown"
        except Exception:
            session_id = "unknown_err"
        user_id = invocation_context.user_id if invocation_context else "anonymous"
        
        # Extract text from content
        text = ""
        if user_message.parts:
            for part in user_message.parts:
                if hasattr(part, "text") and part.text:
                    text += part.text
                    
        self.active_requests[session_id] = {
            "timestamp": datetime.now().isoformat(),
            "user_id": user_id,
            "session_id": session_id,
            "input": text,
            "start_time": time.time()
        }
        return None

    async def after_model_callback(self, *, callback_context, llm_response):
        """Record the completion of a request and calculate latency."""
        try:
            session_id = callback_context.session.id if callback_context and hasattr(callback_context, 'session') and callback_context.session else "unknown"
        except Exception:
            session_id = "unknown_err"
        
        entry = self.active_requests.pop(session_id, None)
        if entry:
            latency = time.time() - entry.pop("start_time")
            
            # Extract response text
            output = ""
            if llm_response.content and llm_response.content.parts:
                for part in llm_response.content.parts:
                    if hasattr(part, "text") and part.text:
                        output += part.text
            
            entry["output"] = output
            entry["latency_ms"] = int(latency * 1000)
            
            # Determine if blocked (proxy check)
            # In a real system, we'd check if any plugin before this one returned a block message
            # For simplicity, we flag common block prefixes
            entry["status"] = "BLOCKED" if any(kw in output for kw in ["cannot process", "cannot share", "limit exceeded", "only help with safe banking"]) else "SUCCESS"
            
            self.logs.append(entry)
            self.export_json()
            
        return llm_response

    def export_json(self):
        """Save logs to the JSON file."""
        try:
            with open(self.log_file, "w", encoding="utf-8") as f:
                json.dump(self.logs, f, indent=2, ensure_ascii=False)
        except Exception as e:
            print(f"Error exporting audit logs: {e}")

    def get_metrics(self):
        """Calculate basic monitoring metrics."""
        total = len(self.logs)
        blocked = sum(1 for log in self.logs if log["status"] == "BLOCKED")
        avg_latency = sum(log["latency_ms"] for log in self.logs) / total if total > 0 else 0
        
        return {
            "total_requests": total,
            "blocked_requests": blocked,
            "block_rate": blocked / total if total > 0 else 0,
            "avg_latency_ms": int(avg_latency)
        }
