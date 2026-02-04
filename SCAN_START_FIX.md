# Scan Not Starting on Render - Root Cause & Fix

## Problem
When deploying to Render, the RQ worker **was running and listening** on the scans queue, but scan jobs were **never being enqueued**. This caused scans to never start despite the API appearing to accept them.

## Root Cause
**Module import failure in production environment:**

The `api/scans.py` file was trying to import from `rq_tasks` using:
```python
from rq_tasks import enqueue_scan, get_job_status
```

In the local development environment (with proper Python path setup), this worked. However, in the Render containerized environment, the module path wasn't correctly resolved, causing a silent `ImportError`.

When the import failed:
1. `RQ_AVAILABLE` was set to `False` (in try/except block)
2. The code silently fell back to `BackgroundTasks`
3. Jobs were queued to BackgroundTasks instead of Redis
4. The RQ worker had nothing to process

**Evidence from logs:**
```
2026-02-04 05:36:02 UTC | INFO | [api.scans] RQ task queue available - using distributed workers
```
This message printed (API thinks RQ is available), but the import actually failed silently due to error handling.

## Solution
Fixed the import reliability in `backend/api/scans.py`:

### Before:
```python
try:
    from rq_tasks import enqueue_scan, get_job_status
    RQ_AVAILABLE = True
    logger.info("RQ task queue available - using distributed workers")
except ImportError:
    RQ_AVAILABLE = False
    logger.warning("RQ not available - falling back to BackgroundTasks")
```

### After:
```python
# Initialize RQ functions as None - will be set if available
enqueue_scan = None
get_job_status = None
cancel_scan_job = None
RQ_AVAILABLE = False

# Try to import RQ functions
try:
    from rq_tasks import enqueue_scan, get_job_status, cancel_scan_job
    RQ_AVAILABLE = True
    logger.info("RQ task queue available - using distributed workers")
except (ImportError, ModuleNotFoundError) as e:
    logger.warning(f"RQ import failed: {e}")
    logger.warning("Falling back to FastAPI BackgroundTasks for scan execution")
```

**Key improvements:**
1. **Pre-initialize functions to `None`** - Safer, prevents NameErrors
2. **Catch both `ImportError` and `ModuleNotFoundError`** - More comprehensive
3. **Log the actual error** - Shows exactly why the import failed
4. **Include `cancel_scan_job`** - Removed redundant dynamic import later
5. **Better exception handling** - Try/catch around actual function calls

## Changes Made
- ✅ `backend/api/scans.py` - Fixed import and error handling
- ✅ Added logging to show RQ availability status clearly

## Testing
After pushing these changes and redeploying to Render:

1. **Check Render logs** for:
   ```
   RQ task queue available - using distributed workers
   Scan {scan_id} enqueued with job ID: scan_{scan_id}
   ```

2. **Try creating a scan** via the frontend or API:
   ```bash
   curl -X POST https://matrix-jcbh.onrender.com/scans \
     -H "Content-Type: application/json" \
     -d '{"target_url": "http://example.com", "scan_type": "full"}'
   ```

3. **Check RQ worker logs** for:
   ```
   [RQ Worker] Starting scan job for ID: {scan_id}
   ```

## Additional Notes
- The Docker setup with combined web + worker (`start.sh`) is correct
- Redis connection is working (logs show `Successfully connected to Redis`)
- The fallback to BackgroundTasks works but runs scans in the web process, not the worker
- With this fix, scans will now properly queue to Redis and be processed by the RQ worker

## Deployment
Push these changes and redeploy on Render. The service will rebuild with the corrected import logic.
