"""Channel adapters.

Inbound channel text is untrusted. It can start a turn. It cannot approve
an action. Approval from Telegram is a button press by the paired owner
only (ARCHITECTURE §12).
"""

from praxis_prime.channels.trust import untrusted_channel_message

__all__ = ["untrusted_channel_message"]
