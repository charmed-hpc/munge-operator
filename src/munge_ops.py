# Copyright (c) Omnivector, LLC <admin@omnivector.solutions>
"""Munge ops - install, remove and return version."""
import hashlib
import logging
import shlex
import subprocess
import tempfile
from base64 import b64decode, b64encode
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Dict, Optional, Union

import charms.operator_libs_linux.v0.apt as apt
import charms.operator_libs_linux.v0.dnf as dnf
from charms.operator_libs_linux.v1.systemd import (
    SystemdError,
    service_running,
    service_start,
    service_stop,
)

logger = logging.getLogger()


def os_release() -> Dict:
    """Return /etc/os-release as a dict."""
    os_release_data = Path("/etc/os-release").read_text()
    os_release_list = [
        item.split("=") for item in os_release_data.strip().split("\n") if item != ""
    ]
    return {k: v.strip('"') for k, v in os_release_list}


class MungeOpsError(Exception):
    """Error raised on munge installation errors."""

    def __init__(self, message: str):
        self.message = message
        super().__init__(self.message)


@dataclass
class MungeData:
    """MungeData container."""

    key: str
    md5: str

    dict = asdict


@dataclass
class MungeOpsBase:
    """MungeOpsBase."""

    _munge_package_name: str = "munge"
    _munge_systemd_service_name: str = "munge"
    _munge_key_path: Path = Path("/etc/munge/munge.key")
    _munge_user: str = "munge"

    def install(self) -> None:
        """Install the munge package here."""
        raise Exception("Inheriting object needs to define this method.")

    def remove(self) -> None:
        """Remove the munge package here."""
        raise Exception("Inheriting object needs to define this method.")

    def version(self) -> str:
        """Return the installed munge package version."""
        raise Exception("Inheriting object needs to define this method.")

    def write_new_munge_key_workflow(self, munge_key: str) -> None:
        """Perform the workflow to write the munge-key."""
        # Stop the munge service if it is running.
        try:
            if service_running(self._munge_systemd_service_name):
                service_stop(self._munge_systemd_service_name)
        except SystemdError as e:
            logger.error(e)
            raise MungeOpsError(e)

        # Base64 decode, remove, and write the munge key.
        key = b64decode(munge_key.encode())
        if self._munge_key_path.exists():
            self._munge_key_path.unlink()
        self._munge_key_path.write_bytes(key)
        # chown the mungekey to the user 'munge'.
        try:
            subprocess.run(
                shlex.split(f"chown {self._munge_user} {self._munge_key_path.as_posix()}")
            )
        except subprocess.CalledProcessError as e:
            logger.error(e)
            raise MungeOpsError(e)
        # chmod the mungekey to 0o400.
        self._munge_key_path.chmod(0o400)

        # Start the munge service.
        try:
            if not service_running(self._munge_systemd_service_name):
                service_start(self._munge_systemd_service_name)
        except SystemdError as e:
            logger.error(e)
            raise MungeOpsError(e)

    def _generate_munge_key(self) -> bytes:
        """Generate a munge key by writing it to a tmp file and return the contents as bytes."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Define the tmp mungekey location.
            tmp_munge_key = f"{tmpdir}/munge.key"

            # Use the `mungekey` command if exists, otherwise generate the mungekey from urandom.
            if Path("/usr/sbin/mungekey").exists():
                cmd = f"mungekey --create --bits=2048 --keyfile={tmp_munge_key}"
            else:
                cmd = f"dd if=/dev/urandom of={tmp_munge_key} bs=1 count=2048"

            # Run the command to generate the mungekey.
            try:
                subprocess.run(shlex.split(cmd))
            except subprocess.CalledProcessError as e:
                logger.error(f"## Error generating mungekey: {e}")
                raise e

            # Munge.key file as bytes.
            munge_key_bytes = Path(tmp_munge_key).read_bytes()
        return munge_key_bytes

    def md5_sum_from_munge_key_on_fs(self) -> str:
        """Return the md5sum from the munge.key that exists on the system."""
        munge_key_bytes = self._munge_key_path.read_bytes()
        return hashlib.md5(munge_key_bytes).hexdigest()

    def generate_munge_data(self, munge_key_as_str: Optional[str] = None) -> MungeData:
        """Generate the munge data."""
        logger.debug("## Generating the munge key.")

        munge_key_bytes = (
            b64decode(munge_key_as_str)
            if munge_key_as_str is not None
            else self._generate_munge_key()
        )

        munge_md5 = hashlib.md5(munge_key_bytes).hexdigest()
        return MungeData(md5=munge_md5, key=b64encode(munge_key_bytes).decode())


@dataclass
class MungeOpsManagerCentos(MungeOpsBase):
    """MungeOpsManager for centos based systems."""

    @property
    def _munge(self) -> "dnf.PackageInfo":
        return dnf.fetch(self._munge_package_name)

    def install(self) -> None:
        """Install munge via dnf."""
        # Install the munge package if not already installed (it shouldn't be as this method
        # is only called in the charm install hook).
        logger.debug(f"Checking if {self._munge_package_name} is already installed on the system.")
        if not self._munge.installed:
            logger.debug(f"{self._munge_package_name} not found on system, installing.")
            try:
                dnf.install(self._munge_package_name)
            except dnf.Error:
                msg = f"Failed to install {self._munge_package_name}."
                logger.error(msg)
                raise MungeOpsError(msg)

    def remove(self) -> None:
        """Remove munge from the system if it exists."""
        logger.debug(f"Checking if {self._munge_package_name} exists on the system.")
        if self._munge.installed:
            logger.debug(f"{self._munge_package_name} found, attempting to remove.")
            try:
                dnf.remove(self._munge_package_name)
            except dnf.Error:
                msg = f"Failed to remove {self._munge_package_name} from the system."
                logger.error(msg)
                raise MungeOpsError(msg)
        else:
            logger.info(f"{self._munge_package_name} already exists on the system.")

    def version(self) -> str:
        """Return the version of the installed munge package."""
        logger.debug(f"Checking if {self._munge_package_name} exists on the system.")
        munge_version = ""
        if self._munge.installed:
            munge_version = self._munge.version
        else:
            raise MungeOpsError(f"{self._munge_package_name} not installed.")
        return munge_version


@dataclass
class MungeOpsManagerUbuntu(MungeOpsBase):
    """MungeOpsManager for debian based systems."""

    @property
    def _munge(self) -> "apt.DebianPackage":
        try:
            return apt.DebianPackage.from_system(self._munge_package_name)
        except apt.PackageNotFoundError as e:
            logger.error(e)
            raise MungeOpsError(e)

    def install(self) -> None:
        """Install munge via apt-get."""
        if not self._munge.present:
            try:
                self._munge.ensure(apt.PackageState.Latest)
            except apt.PackageNotFoundError as e:
                logger.error(e)
                raise MungeOpsError(e)

    def remove(self) -> None:
        """Remove munge from the system if it exists."""
        if self._munge.present:
            try:
                self._munge.ensure(apt.PackageState.Absent)
            except apt.PackageError as e:
                logger.error(e)
                raise MungeOpsError(e)

    def version(self) -> str:
        """Return the munge version if present."""
        munge_version = ""
        if self._munge.present:
            try:
                munge_version = self._munge.fullversion
            except apt.PackageError as e:
                logger.error(e)
                raise MungeOpsError(e)
        return munge_version


def get_munge_ops_manager_for_os() -> Union[MungeOpsManagerCentos, MungeOpsManagerUbuntu]:
    """Determine the operating system and return the correct MungeOpsManager."""
    return MungeOpsManagerUbuntu() if os_release()["ID"] == "ubuntu" else MungeOpsManagerCentos()
