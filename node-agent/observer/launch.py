"""Run a local nDPId alongside the agent, exiting when EITHER task finishes.

The agent deliberately returns after max_uptime_hours. Docker must see that exit
so restart: unless-stopped can start a fresh agent rather than a daemon-only shell.
"""
import asyncio
import os
from pathlib import Path
from src.collectors.ndpi_daemon import NdpiDaemon
from src.main import run_agent


async def supervise(agent, monitor):
    tasks = [asyncio.create_task(agent), asyncio.create_task(monitor)]
    try:
        done, _ = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        for task in done:
            task.result()  # Propagate failures as well as normal agent completion.
    finally:
        for task in tasks:
            if not task.done():
                task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)


async def monitor(daemon):
    while True:
        await asyncio.sleep(5)
        if not daemon.running:
            raise RuntimeError('nDPI daemon stopped')
        path = Path('/var/log/remnanode/access.log')
        if path.exists() and path.stat().st_size > 32 * 1024 * 1024:
            import shutil
            for i in (2, 1):
                old = Path(str(path) + '.' + str(i))
                if old.exists():
                    old.replace(str(path) + '.' + str(i + 1))
            shutil.copyfile(path, str(path) + '.1')
            with path.open('r+b') as file:
                file.truncate(0)


async def main():
    daemon = NdpiDaemon(os.environ['AGENT_NDPI_SOCKET_PATH'],
                        interface=os.environ.get('AGENT_NDPI_INTERFACE') or None)
    try:
        state = await daemon.start()
        print('LOCAL_NDPI_START', state, flush=True)
        if not state.get('started'):
            raise RuntimeError('nDPI daemon failed')
        await supervise(run_agent(), monitor(daemon))
    finally:
        await daemon.stop()


if __name__ == '__main__':
    asyncio.run(main())
