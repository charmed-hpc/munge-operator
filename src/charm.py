#!/usr/bin/env python3
# Copyright (c) Omnivector, LLC <admin@omnivector.solutions>
"""Munge Operator Charm."""
import logging
from typing import Union

from munge_ops import MungeData, MungeOpsError, get_munge_ops_manager_for_os
from munge_provider import MungeProvider
from ops.charm import CharmBase
from ops.main import main
from ops.model import ActiveStatus, BlockedStatus, Secret, SecretNotFoundError, WaitingStatus

logger = logging.getLogger()


class MungeOperator(CharmBase):
    """Munge Operator."""

    def __init__(self, *args):
        """Initialize the charm."""
        super().__init__(*args)

        self._munge_data_secret_label = "mungedata"

        # Integrations
        self._munge_provider = MungeProvider(self, "munge")

        event_handler_bindings = {
            self.on.install: self._on_install,
            self.on.start: self._on_start,
            self.on.remove: self._on_remove,
            self.on.secret_changed: self._on_secret_changed,
            # Actions
            self.on.rotate_munge_key_action: self._on_rotate_munge_key,
            self.on.replace_munge_key_action: self._on_replace_munge_key,
        }
        for event, handler in event_handler_bindings.items():
            self.framework.observe(event, handler)

    def _get_munge_data_secret(self) -> Union[Secret, None]:
        """Get the munge secret if it exists."""
        try:
            munge_data_secret = self.model.get_secret(label=self._munge_data_secret_label)
        except SecretNotFoundError:
            logger.debug("Secret not found in backend.")
            return None
        return munge_data_secret

    def _munge_data_from_secret(self) -> Union[MungeData, None]:
        """Get the munge secret if it exists."""
        if (munge_data_secret := self._get_munge_data_secret()) is not None:
            munge_data = munge_data_secret.peek_content()
        else:
            return None
        return MungeData(**munge_data)

    def _on_install(self, event) -> None:
        """Install munge."""
        install_msg = "Installing munge..."
        logger.info(install_msg)
        self.unit.status = WaitingStatus(install_msg)

        try:
            get_munge_ops_manager_for_os().install()
        except MungeOpsError as e:
            logger.error(e)
            self.unit.status = BlockedStatus("Error installing munge. Please debug.")
            event.defer()
            return

    def _on_start(self, event) -> None:
        """Configure the munge-key and start munge."""
        msg = "Configuring the munge-key and starting munge."
        logger.info(msg)
        self.unit.status = WaitingStatus(msg)

        munge_data = self._munge_data_from_secret()
        munge_ops_manager = get_munge_ops_manager_for_os()

        if munge_data is None:
            # Leader creates the first mungekey, after this, any unit
            # can update the rotate the update/rotate the key.
            if self.model.unit.is_leader():
                munge_data = munge_ops_manager.generate_munge_data()
                # Add the munge_data to the secrets store.
                self.app.add_secret(content=munge_data.dict(), label=self._munge_data_secret_label)
            else:
                logger.debug("## Deferring event until munge_data secret exists.")
                event.defer()
                return

        # Run the workflow to write the munge.key.
        munge_ops_manager.write_new_munge_key_workflow(munge_data.key)

        # Tell related unit that munge is available.
        self._munge_provider.set_munge_available()

        # Set the charm workload version and status.
        self.unit.set_workload_version(munge_ops_manager.version())
        self.unit.status = ActiveStatus("Ready")

    def _on_remove(self, event) -> None:
        """Remove Munge from the system."""
        msg = "## Removing Munge from the system."
        logger.info(msg)
        self.unit.status = WaitingStatus(msg)

        try:
            get_munge_ops_manager_for_os().remove()
        except MungeOpsError as e:
            logger.error(e)
            self.unit.status = BlockedStatus(e)
            event.defer()
            return

    def _on_rotate_munge_key(self, event) -> None:
        """Rotate the munge-key."""
        msg = "Updating munge-key in the secret store."
        logger.info(msg)
        self.unit.status = WaitingStatus(msg)

        # Update the secret labeled 'mungedata' with the new content.
        if (munge_data_secret := self._get_munge_data_secret()) is not None:
            munge_data = get_munge_ops_manager_for_os().generate_munge_data()
            munge_data_secret.set_content(munge_data.dict())

            # Set the action results and charm status.
            result_msg = f"## Munge key rotated. MD5: {munge_data.md5}"
            logger.info(result_msg)
        else:
            result_msg = "## Munge key could not be rotated."
            logger.error(result_msg)

        event.set_results({"message": result_msg})
        self.unit.status = ActiveStatus("Ready")

    def _on_replace_munge_key(self, event) -> None:
        """Get the munge key from the secrets store and perform the write key workflow."""
        msg = "Replacing the munge-key."
        logger.info(msg)
        self.unit.status = WaitingStatus(msg)

        if (munge_data := self._munge_data_from_secret()) is not None:
            logger.debug("Obtained MungeData from secret store.")
            logger.debug("Writing munge key to /etc/munge/munge.key")
            get_munge_ops_manager_for_os().write_new_munge_key_workflow(munge_data.key)
            result_msg = f"Munge key replaced. MD5: {munge_data.md5}"
            logger.info(result_msg)
            self.unit.status = ActiveStatus("Ready")
            return

        result_msg = "Munge key could not be replaced."
        logger.error(result_msg)
        event.set_results({"message": result_msg})

    def _on_secret_changed(self, event) -> None:
        """Handle the secret changed event."""
        munge_key_md5_from_secret = self._munge_data_from_secret().md5
        munge_key_md5_from_fs = get_munge_ops_manager_for_os().md5_sum_from_munge_key_on_fs()
        if munge_key_md5_from_secret != munge_key_md5_from_fs:
            msg = "The munge-key has changed, use the replace-munge-key action to replace."
            self.unit.status = BlockedStatus(msg)
            logger.debug(msg)
            event.defer()


if __name__ == "__main__":
    main(MungeOperator)
