"""
MIT License

Copyright (c) 2023 Oviyan Gandhi

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""
from __future__ import annotations
from functools import wraps
from fastapi.responses import JSONResponse
from limits import parse
from limits.aio.storage import MemoryStorage
from limits.aio.strategies import MovingWindowRateLimiter
from time import time

class RateLimiter:
    def __init__(self, global_lim: str):
        self.memstore = MemoryStorage()
        self.global_lim = parse(global_lim)
        self.mv = MovingWindowRateLimiter(self.memstore)

    def limit(self, interval: str):
        """Add a rate limit to the coroutine based on the arg given.
        arg must be passed as a keyword argument."""
        lim = parse(interval)
        def decorator(coro):
            @wraps(coro)
            async def wrapper(*args, **kwargs):
                t = time()
                ip: str = kwargs["request"].client.host
                passed = await self.mv.hit(self.global_lim, "global", ip)
                stats = await self.mv.get_window_stats(self.global_lim, "global", ip)
                headers = {
                    "X-Rate-Limit-Global-Limit": str(self.global_lim.amount),
                    "X-Rate-Limit-Global-Remaining": str(stats.remaining),
                    "X-Rate-Limit-Global-Reset": str(stats.reset_time)
                }
                reset_time = stats.reset_time
                if passed:
                    passed = await self.mv.hit(lim, coro.__name__, ip)
                    stats = await self.mv.get_window_stats(lim, coro.__name__, ip)
                    reset_time = stats.reset_time
                else:
                    stats = await self.mv.get_window_stats(lim, coro.__name__, ip)
                headers.update({
                    "X-Rate-Limit-Limit": str(lim.amount),
                    "X-Rate-Limit-Remaining": str(stats.remaining),
                    "X-Rate-Limit-Reset": str(stats.reset_time)
                })
                if passed:
                    response: JSONResponse = await coro(*args, **kwargs)
                    response.init_headers(headers)
                else:
                    response = JSONResponse(
                        status_code=429,
                        headers=headers,
                        content={
                            "success": False, "status": 429,
                            "errors": [{
                                "code": "TOO_MANY_REQUESTS",
                                "description": "You are being rate limited, please try again"
                                    + f" after {reset_time - t:.2f} seconds"
                            }]
                        }
                    )
                return response
            return wrapper
        return decorator