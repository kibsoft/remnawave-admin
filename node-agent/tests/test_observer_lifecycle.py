import asyncio
import importlib.util
from pathlib import Path
from unittest.mock import AsyncMock, Mock, patch
import pytest

spec = importlib.util.spec_from_file_location('observer_launch', Path(__file__).parents[1]/'observer'/'launch.py')
launch = importlib.util.module_from_spec(spec)
spec.loader.exec_module(launch)

@pytest.mark.asyncio
async def test_normal_agent_uptime_exit_cancels_long_lived_monitor():
    stopped = asyncio.Event()
    async def agent():
        await asyncio.sleep(0)
    async def monitor():
        try:
            await asyncio.Event().wait()
        finally:
            stopped.set()
    await asyncio.wait_for(launch.supervise(agent(), monitor()), 1)
    assert stopped.is_set()

@pytest.mark.asyncio
@pytest.mark.parametrize('failed', ['agent', 'monitor'])
async def test_task_failure_stops_sibling_and_propagates(failed):
    stopped = asyncio.Event()
    async def fail():
        await asyncio.sleep(0)
        raise RuntimeError('failed')
    async def wait():
        try:
            await asyncio.Event().wait()
        finally:
            stopped.set()
    pair = (fail(), wait()) if failed == 'agent' else (wait(), fail())
    with pytest.raises(RuntimeError, match='failed'):
        await asyncio.wait_for(launch.supervise(*pair), 1)
    assert stopped.is_set()

@pytest.mark.asyncio
async def test_external_shutdown_stops_both_tasks():
    stopped = [False, False]
    async def wait(i):
        try:
            await asyncio.Event().wait()
        finally:
            stopped[i] = True
    task = asyncio.create_task(launch.supervise(wait(0), wait(1)))
    await asyncio.sleep(.01)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert all(stopped)

@pytest.mark.asyncio
@pytest.mark.parametrize('started', [True, False])
async def test_daemon_cleanup_runs_on_normal_exit_and_start_failure(monkeypatch, started):
    monkeypatch.setenv('AGENT_NDPI_SOCKET_PATH', '/tmp/test.sock')
    daemon = Mock(start=AsyncMock(return_value={'started': started}), stop=AsyncMock())
    with patch.object(launch, 'NdpiDaemon', return_value=daemon), patch.object(launch, 'run_agent', AsyncMock()), patch.object(launch, 'monitor', AsyncMock()):
        if started:
            await launch.main()
        else:
            with pytest.raises(RuntimeError, match='nDPI daemon failed'):
                await launch.main()
    daemon.stop.assert_awaited_once()
