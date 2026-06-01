from trezor.messages import ShrincsSignature
import ubinascii
import trezorui_api
from trezor.enums import ButtonRequestType
from trezor.ui.layouts.common import raise_if_not_confirmed
from trezor.ui.layouts.progress import progress as show_progress

from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from trezor.messages import ShrincsSign

CACHED_SK: bytes | None = None

async def shrincs_sign(msg: ShrincsSign) -> ShrincsSignature:
    global CACHED_SK
    from trezor import crypto

    await raise_if_not_confirmed(
        trezorui_api.confirm_shrincs(),
        "shrincs_sign",
        ButtonRequestType.Other,
    )

    if CACHED_SK is None:
        # keychain = await get_keychain("secp256k1", [AlwaysMatchingSchema])
        # node = keychain.derive(msg.address_n)

        # raw_pk = node.private_key()
        # pk_bytes = bytes(raw_pk)

        # CACHED_SK = crypto.shrincs_expand_sk(pk_bytes)
        CACHED_SK = ubinascii.unhexlify("0517400a7d4f5a532d4f34b077182caf1a79e406404e29a7feed94aa546330ac00ae2c282f33b319d83b705b4b5487c618311f77a5283cf39aabaf35dc3dfd79918fd17d889f34eb76a9901c93a2015eda5a08dc47d1e05d0d4d816f72e78e27")

    prog = show_progress("Signing... 0%", title="SHRINCS", indeterminate=False)
    prog.report(0)

    def reporter(value: int) -> None:
        prog.report(value, "Signing... {}%".format(value // 10))

    if msg.stateless:
        signature_bytes = crypto.shrincs_sign_stateless(CACHED_SK, msg.data, reporter)
        prog.report(1000, "Signing... 100%")
    else:
        from trezor import config
        import struct

        APP_ID, STATE_KEY = 0x20, 0x01
        res = config.get(APP_ID, STATE_KEY)

        # if res is None:
        #     current_state = (0, 1)
        # else:
        #     current_state = struct.unpack("<II", res)

        current_state = (1, 1)

        signature_bytes, new_state = crypto.shrincs_sign_stateful(CACHED_SK, current_state, msg.data, reporter)
        prog.report(1000, "Signing... 100%")

        new_state_bytes = struct.pack("<II", *new_state)
        config.set(APP_ID, STATE_KEY, new_state_bytes)

    return ShrincsSignature(signature=signature_bytes)