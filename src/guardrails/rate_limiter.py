"""
Lab 11 — Rate Limiter Plugin
Implements a sliding window rate limiter to prevent abuse.
"""
import time
from collections import defaultdict, deque
from google.adk.plugins import base_plugin
from google.genai import types

class RateLimitPlugin(base_plugin.BasePlugin):
    """Plugin that blocks users who send too many requests in a time window.
    
    This layer prevents Denial of Service (DoS) and brute-force attacks
    by limiting the number of requests per user.
    """
    
    def __init__(self, max_requests=10, window_seconds=60):
        super().__init__(name="rate_limiter")
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.user_windows = defaultdict(deque)
        self.blocked_count = 0

    async def on_user_message_callback(self, *, invocation_context, user_message):
        """Check if the user has exceeded their rate limit."""
        user_id = invocation_context.user_id if invocation_context else "anonymous"
        now = time.time()
        window = self.user_windows[user_id]

        # Remove expired timestamps from the front of the deque
        while window and window[0] < now - self.window_seconds:
            window.popleft()

        if len(window) >= self.max_requests:
            self.blocked_count += 1
            wait_time = int(self.window_seconds - (now - window[0]))
            return types.Content(
                role="model",
                parts=[types.Part.from_text(
                    text=f"Rate limit exceeded. Please wait {wait_time} seconds before trying again."
                )],
            )

        # Allow request and record timestamp
        window.append(now)
        return None
