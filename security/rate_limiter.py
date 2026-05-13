"""
security/rate_limiter.py
 
Rate limiting module.
Blocks identifiers (IP addresses or user IDs) that exceed a request
quota within a rolling time window.  Prevents brute-force attacks
and API abuse.
 
In production this is backed by Redis so limits are shared across
all application instances.  This implementation uses in-process memory
and is suitable for single-process deployments and testing.
"""

import time
from collections import defaultdict

class RateLimiter:
    """Sliding-window rate limiter.
 
    Each call to is_allowed() records the current timestamp for the
    given identifier.  On every call, timestamps older than the window
    are discarded so the count always reflects recent activity only.
 
    Args:
        max_requests:    Maximum number of requests permitted per window.
        window_seconds:  Length of the rolling time window in seconds.
    """

    def __init__(self, max_requests: int = 5, window_seconds: int = 60):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        # defaultdict(list) → automatically creates an empty list for new keys
        self._requests: dict = defaultdict(list)

    def is_allowed(self, identifier):
        """Check whether the identifier may make another request.
 
        Args:
            identifier: IP address, user ID, or any unique caller key.
 
        Returns:
            True if the request is within the quota, False if blocked.
        """
        now = time.time()

        # Discard timestamps outside the current window
        self._requests[identifier] = [
            t for t in self._requests[identifier]
            if now - t < self.window_seconds
        ]

        if len(self._requests[identifier]) >= self.max_requests:
            return False # quota exceeded — block the request
        
        # Record this request and allow it
        self._requests[identifier].append(now)
        return True
    
    def remaining_requests(self, identifier):
        """Return the number of requests the identifier can still make.
 
        Args:
            identifier: The caller key to query.
 
        Returns:
            Remaining request count within the current window.
        """
        now = time.time()
        recent = [
            t for t in self._requests[identifier]
            if now - t < self.window_seconds
        ]
        return max(0, self.max_requests - len(recent))