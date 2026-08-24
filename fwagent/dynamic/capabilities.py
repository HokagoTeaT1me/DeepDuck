from __future__ import annotations

import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class DynamicCapabilities:
    docker: bool
    qemu_arm: bool
    qemu_mips: bool
    loop_devices: bool
    tun: bool
    kvm: bool
    userspace_image_builder: bool
    qemu_user_network: bool
    native_firmae: bool
    compatible_backend: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "docker": self.docker,
            "qemu_arm": self.qemu_arm,
            "qemu_mips": self.qemu_mips,
            "loop_devices": self.loop_devices,
            "tun": self.tun,
            "kvm": self.kvm,
            "userspace_image_builder": self.userspace_image_builder,
            "qemu_user_network": self.qemu_user_network,
            "native_firmae": self.native_firmae,
            "compatible_backend": self.compatible_backend,
        }


def detect_capabilities() -> DynamicCapabilities:
    loop_devices = any(Path("/dev").glob("loop*"))
    tun = Path("/dev/net/tun").exists()
    kvm = Path("/dev/kvm").exists()
    qemu_arm = shutil.which("qemu-system-arm") is not None
    qemu_mips = shutil.which("qemu-system-mips") is not None
    userspace_image_builder = shutil.which("mke2fs") is not None
    firmae_run = Path("/opt/FirmAE/run.sh").exists()
    qemu_user_network = qemu_arm or qemu_mips
    compatible_backend = userspace_image_builder and qemu_user_network
    native_firmae = firmae_run and loop_devices and tun
    return DynamicCapabilities(
        docker=shutil.which("docker") is not None or Path("/.dockerenv").exists(),
        qemu_arm=qemu_arm,
        qemu_mips=qemu_mips,
        loop_devices=loop_devices,
        tun=tun,
        kvm=kvm,
        userspace_image_builder=userspace_image_builder,
        qemu_user_network=qemu_user_network,
        native_firmae=native_firmae,
        compatible_backend=compatible_backend,
    )
