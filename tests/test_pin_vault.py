from signur.pin_vault import PinVault


def _vault(clock: list[float], forget_after_seconds: float = 60.0) -> PinVault:
    return PinVault(forget_after_seconds=forget_after_seconds, clock=lambda: clock[0])


def test_a_held_pin_is_handed_over_once() -> None:
    clock = [0.0]
    vault = _vault(clock)
    vault.hold("job", "654321")

    assert vault.take("job") == "654321"
    assert vault.take("job") is None


def test_a_job_nobody_left_a_pin_for_gets_nothing() -> None:
    assert _vault([0.0]).take("job") is None


def test_a_pin_nobody_collects_is_forgotten() -> None:
    """A queue that never moves must not keep a PIN in memory for ever."""
    clock = [0.0]
    vault = _vault(clock, forget_after_seconds=60.0)
    vault.hold("job", "654321")

    clock[0] = 61.0

    assert vault.take("job") is None


def test_a_pin_is_still_there_just_before_the_window_closes() -> None:
    clock = [0.0]
    vault = _vault(clock, forget_after_seconds=60.0)
    vault.hold("job", "654321")

    clock[0] = 59.0

    assert vault.take("job") == "654321"


def test_holding_again_replaces_the_pin_and_its_deadline() -> None:
    clock = [0.0]
    vault = _vault(clock, forget_after_seconds=60.0)
    vault.hold("job", "111111")

    clock[0] = 50.0
    vault.hold("job", "222222")
    clock[0] = 100.0

    assert vault.take("job") == "222222"


def test_a_pin_can_be_dropped_without_being_used() -> None:
    clock = [0.0]
    vault = _vault(clock)
    vault.hold("job", "654321")

    vault.discard("job")

    assert vault.take("job") is None


def test_dropping_a_pin_that_is_not_there_is_harmless() -> None:
    _vault([0.0]).discard("job")


def test_a_stale_pin_does_not_survive_because_another_job_arrives() -> None:
    """Whoever touches the vault sweeps it, so nothing lingers unnoticed."""
    clock = [0.0]
    vault = _vault(clock, forget_after_seconds=60.0)
    vault.hold("dimenticato", "111111")

    clock[0] = 61.0
    vault.hold("nuovo", "222222")

    assert vault.held_count() == 1
