import logging
import uuid
from typing import Optional

from redis import Redis
from rq import Queue

from app.config import settings

logger = logging.getLogger(__name__)

QUEUE_NAME = "mailrecon"
_redis_conn: Optional[Redis] = None


def get_redis_connection() -> Optional[Redis]:
    global _redis_conn
    if _redis_conn is None:
        try:
            conn = Redis.from_url(settings.REDIS_URL, socket_connect_timeout=2)
            conn.ping()
            _redis_conn = conn
        except Exception as e:
            logger.warning(f"Redis is not available at {settings.REDIS_URL}: {e}. Task queue will run in offline mode.")
            return None
    return _redis_conn


def enqueue_case_analysis(case_id: uuid.UUID) -> bool:
    """Enqueue analysis of a case in RQ. Returns True if queued, False if offline/failed."""
    try:
        conn = get_redis_connection()
        if conn is None:
            logger.info(f"Skipping queue for case {case_id}: Redis connection is not available.")
            return False

        q = Queue(QUEUE_NAME, connection=conn)
        from app.tasks.jobs import process_case_job
        job = q.enqueue(process_case_job, str(case_id))
        logger.info(f"Queued analysis job {job.id} for case {case_id}")
        return True
    except Exception as e:
        logger.warning(f"Failed to enqueue case {case_id}: {e}")
        return False
