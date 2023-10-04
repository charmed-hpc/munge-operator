# Copyright (c) Omnivector, LLC <admin@omnivector.solutions>
"""MungeProvider."""
import logging

from ops.framework import Object

logger = logging.getLogger()


class MungeProvider(Object):
    """MungeProvider."""

    def __init__(self, charm, relation_name):
        """Initialize and observe."""
        super().__init__(charm, relation_name)
        self._charm = charm
        self._relation_name = relation_name

    @property
    def _relation(self):
        return self.framework.model.get_relation(self._relation_name)

    def set_munge_available(self) -> None:
        """Set the munge available in the unit relation data."""
        if not self._relation:
            logger.debug("## Relation doesn't exist, skipping setting the munge_status.")
            return

        self._relation.data[self.model.unit]["munge_status"] = "available"
        logger.debug("## Munge: available")
