import time
from mitmproxy import ctx, http


class AutoPrune:
    # default parameters (you can edit them at your convenience)
    interval   = 30        # seconds between checks
    max_flows  = 1000      # how many flows to keep in memory (will be kept the most recent ones)
    max_age    = 600       # maximum age of flows in seconds (will be removed if older than this)

    def __init__(self):
        self._last_check = 0.0

    def running(self):
        self._last_check = time.time()
        ctx.log.info(
            f"[AutoPrune] attivo: interval={self.interval}s "
            f"max_flows={self.max_flows} max_age={self.max_age}s"
        )

    def tick(self):
        now = time.time()
        if now - self._last_check >= self.interval:
            self._cleanup(now)
            self._last_check = now

    # secondary hook: if you want to do something on each request/response
    def request(self, flow: http.HTTPFlow):
        self.tick()

    # ------- cleanup logic -------
    def _cleanup(self, now):
        view = ctx.master.view
        if not view:
            return

        # 1) remove flows older than max_age
        too_old = [f for f in view if now - (f.request.timestamp_start or now) > self.max_age]
        if too_old:
            view.remove(too_old)

        # 2) if there are too many flows, keep only the most recent ones
        if len(view) > self.max_flows:
            recent_sorted = sorted(
                view, key=lambda f: f.request.timestamp_start, reverse=True
            )
            keep = recent_sorted[: self.max_flows]
            to_remove = set(view) - set(keep)
            view.remove(to_remove)

        ctx.log.info(f"[AutoPrune] flussi in memoria: {len(view)}")


addons = [AutoPrune()]