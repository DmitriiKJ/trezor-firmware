from trezor.messages import SlhDsaSignature
import ubinascii
import trezorui_api
from trezor.enums import ButtonRequestType
from trezor.ui.layouts.common import raise_if_not_confirmed
from trezor.ui.layouts.progress import progress as show_progress

from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from trezor.messages import SlhDsaSign

CACHED_SK: bytes | None = None

async def slh_dsa_sign(msg: SlhDsaSign) -> SlhDsaSignature:
    global CACHED_SK
    from trezor import crypto

    await raise_if_not_confirmed(
        trezorui_api.confirm_action(
            title="SLH-DSA",
            action="Sign message?",
            description=None,
            verb="CONFIRM",
        ),
        "slh_dsa_sign",
        ButtonRequestType.Other,
    )

    if CACHED_SK is None:
        # keychain = await get_keychain("secp256k1", [AlwaysMatchingSchema])
        # node = keychain.derive(msg.address_n)

        # raw_pk = node.private_key()
        # pk_bytes = bytes(raw_pk)

        # CACHED_SK = crypto.shrincs_expand_sk(pk_bytes)
        CACHED_SK = ubinascii.unhexlify("0517400a7d4f5a532d4f34b077182caf1a79e406404e29a7feed94aa546330ac00ae2c282f33b319d83b705b4b5487c618311f77a5283cf39aabaf35dc3dfd79")

    prog = show_progress("Signing... 0%", title="SLH-DSA", indeterminate=False)
    prog.report(0)

    def reporter(value: int) -> None:
        prog.report(value, "Signing... {}%".format(value // 10))

    signature_bytes = crypto.slh_dsa_sign(CACHED_SK, msg.data, msg.is_standart, reporter)
    prog.report(1000, "Signing... 100%")

    return SlhDsaSignature(signature=signature_bytes)