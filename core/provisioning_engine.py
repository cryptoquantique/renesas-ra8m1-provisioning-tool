"""
Provisioning engine for device provisioning workflow.

This module provides the core provisioning engine that orchestrates
the complete device provisioning workflow including:
- Key generation and management
- Certificate generation
- Firmware signing
- Device programming
"""

from dataclasses import dataclass
from enum import Enum, auto
from typing import Callable, Dict, List, Optional, Any

from utils.logging import get_logger

logger = get_logger(__name__)


class ProvisioningStep(Enum):
    """Provisioning workflow steps."""
    KEY_GENERATION = auto()
    CERTIFICATE_GENERATION = auto()
    DEVICE_INITIALIZATION = auto()
    KEY_INJECTION = auto()
    BOOTLOADER_PROGRAMMING = auto()
    CERTIFICATE_PROGRAMMING = auto()
    APPLICATION_PROGRAMMING = auto()
    VERIFICATION = auto()
    DEVICE_LOCKING = auto()


class ProvisioningState(Enum):
    """Provisioning state machine states."""
    IDLE = auto()
    RUNNING = auto()
    PAUSED = auto()
    COMPLETED = auto()
    FAILED = auto()
    CANCELLED = auto()


@dataclass
class ProvisioningResult:
    """Result of a provisioning operation."""
    success: bool
    step: ProvisioningStep
    message: str
    data: Optional[Dict[str, Any]] = None


class ProvisioningEngine:
    """
    Core provisioning engine.

    Orchestrates the complete device provisioning workflow,
    managing state transitions and step execution.
    """

    def __init__(self, config):
        """
        Initialize provisioning engine.

        Args:
            config: ProvisioningToolConfig instance
        """
        self.config = config
        self._state = ProvisioningState.IDLE
        self._current_step: Optional[ProvisioningStep] = None
        self._progress_callbacks: List[Callable[[int, str], None]] = []
        self._step_results: Dict[ProvisioningStep, ProvisioningResult] = {}

        logger.info("Provisioning engine initialized")

    @property
    def state(self) -> ProvisioningState:
        """Get current provisioning state."""
        return self._state

    @property
    def current_step(self) -> Optional[ProvisioningStep]:
        """Get current provisioning step."""
        return self._current_step

    def add_progress_callback(self, callback: Callable[[int, str], None]) -> None:
        """
        Add a progress callback.

        Args:
            callback: Function to call with (percentage, message)
        """
        self._progress_callbacks.append(callback)

    def remove_progress_callback(self, callback: Callable[[int, str], None]) -> None:
        """Remove a progress callback."""
        if callback in self._progress_callbacks:
            self._progress_callbacks.remove(callback)

    def _report_progress(self, percentage: int, message: str) -> None:
        """Report progress to all callbacks."""
        for callback in self._progress_callbacks:
            try:
                callback(percentage, message)
            except Exception as e:
                logger.error(f"Progress callback error: {e}")

    def start(self, device_info=None, key_data=None) -> bool:
        """
        Start the provisioning workflow.

        Args:
            device_info: Target device information
            key_data: Key provisioning data

        Returns:
            True if started successfully
        """
        if self._state == ProvisioningState.RUNNING:
            logger.warning("Provisioning already in progress")
            return False

        self._state = ProvisioningState.RUNNING
        self._step_results.clear()
        self._report_progress(0, "Starting provisioning workflow...")

        logger.info("Provisioning workflow started")
        return True

    def stop(self) -> bool:
        """
        Stop the provisioning workflow.

        Returns:
            True if stopped successfully
        """
        if self._state != ProvisioningState.RUNNING:
            return False

        self._state = ProvisioningState.CANCELLED
        self._report_progress(0, "Provisioning cancelled by user")

        logger.info("Provisioning workflow cancelled")
        return True

    def pause(self) -> bool:
        """Pause the provisioning workflow."""
        if self._state != ProvisioningState.RUNNING:
            return False

        self._state = ProvisioningState.PAUSED
        return True

    def resume(self) -> bool:
        """Resume the provisioning workflow."""
        if self._state != ProvisioningState.PAUSED:
            return False

        self._state = ProvisioningState.RUNNING
        return True

    def get_step_result(self, step: ProvisioningStep) -> Optional[ProvisioningResult]:
        """Get the result of a specific step."""
        return self._step_results.get(step)

    def get_all_results(self) -> Dict[ProvisioningStep, ProvisioningResult]:
        """Get all step results."""
        return self._step_results.copy()

    def reset(self) -> None:
        """Reset the provisioning engine to initial state."""
        self._state = ProvisioningState.IDLE
        self._current_step = None
        self._step_results.clear()
        logger.info("Provisioning engine reset")
