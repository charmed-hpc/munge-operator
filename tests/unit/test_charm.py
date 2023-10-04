#!/usr/bin/env python3
import unittest

from charm import MungeOperator
from ops.testing import Harness


class TestCharm(unittest.TestCase):
    """Unit test suite for nvidia driver operator."""

    def setUp(self) -> None:
        """Set up unit test."""
        self.harness = Harness(MungeOperator)
        self.addCleanup(self.harness.cleanup)
        self.harness.begin()

    def test_pass(self) -> None:
        """Test pass."""
        pass
