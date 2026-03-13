pub mod codec;
pub mod lora_frame;
pub mod types;
pub mod wire;

// Cap'n Proto schemas are in schemas/ for protocol documentation.
// Wire encoding uses our own binary codec for zero-dependency builds.
