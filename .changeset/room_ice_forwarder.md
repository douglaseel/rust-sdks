---
livekit: minor
livekit-ffi: minor
---

Add `RoomOptions::ice_forwarder` (`RtcConfig.ice_forwarder` over FFI) to send all of a room connection's media through a stateless UDP forwarder that routes ICE checks by their username fragment.
