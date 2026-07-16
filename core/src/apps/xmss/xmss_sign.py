import ubinascii

from trezor.messages import XMSSSignature, XMSSKeyGen, XMSSSk
import trezorui_api
from trezor.enums import ButtonRequestType
from trezor.ui.layouts.common import raise_if_not_confirmed
from trezor.ui.layouts.progress import progress as show_progress

from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from trezor.messages import XMSSSign

# SHA2, h=10 (2^10 signatures), w=16, n=16
XMSS_OID = 0x000000ff

CACHED_SK: bytes | None = None

async def xmss_sign(msg: XMSSSign) -> XMSSSignature:
    global CACHED_SK
    from trezor import crypto

    # await raise_if_not_confirmed(
    #     trezorui_api.confirm_action(
    #         title="XMSS",
    #         action="Sign message?",
    #         description=None,
    #         verb="CONFIRM",
    #     ),
    #     "xmss_sign",
    #     ButtonRequestType.Other,
    # )

    # if CACHED_SK is None:
        # raise ValueError("No XMSS key loaded")
        
    CACHED_SK = ubinascii.unhexlify("000000ff00000000b809496f05c121c581b0c7d570a9f7212230654732ee37386867f889755ce3dc2eee098dfb7b52a4042220ab6ff8a702829765a3d900a6359204ef3d352c6023")
        

    prog = show_progress("Signing... 0%", title="XMSS", indeterminate=False)
    prog.report(0)

    def sign_reporter(value: int) -> None:
        prog.report(value, "Signing... {}%".format(value // 10))

    sig_bytes, CACHED_SK = crypto.xmss_sign(CACHED_SK, msg.data, sign_reporter)
    prog.report(1000, "Signing... 100%")

    return XMSSSignature(signature=sig_bytes)

async def xmss_key_gen(msg: XMSSKeyGen) -> XMSSSk:
    from trezor import crypto

    prog = show_progress("Keygen... 0%", title="XMSS", indeterminate=False)
    prog.report(0)

    def keygen_reporter(value: int) -> None:
        prog.report(value, "Keygen... {}%".format(value // 10))

    sk_bytes, pk_bytes = crypto.xmss_keygen(msg.bytes, XMSS_OID, keygen_reporter)
    prog.report(1000, "Keygen... 100%")

    return XMSSSk(sk_bytes=sk_bytes)
