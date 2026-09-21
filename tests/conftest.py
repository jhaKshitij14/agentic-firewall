import asyncio

import pytest

from attacks.harness import make_env


@pytest.fixture
def env():
    return asyncio.run(make_env())


@pytest.fixture
def run():
    """Run a coroutine to completion: run(env.call('alice', 'search_news', {...}))."""
    return asyncio.run
