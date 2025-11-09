// it seems certain XOR-differences in the input and output have a high
// correlation, regardless of the key in use.
//
// This code measures the correlation over all inputs (runs about 1
// minute in release mode)
//
// See:
// https://www.ietf.org/mail-archive/web/cfrg/current/msg09495.html
//
// Run with:
//
//     cargo run --release --example attack

extern crate ipcrypt;
extern crate rand;

use ipcrypt::{
	encrypt,
	State,
};
use rand::Rng;

fn main() {
	let mut rng = rand::thread_rng();

	let key: ipcrypt::Key = rng.gen();

	let delta_input: State = State::from([0x0a, 0x02, 0x00, 0x00]);
	let delta_output: State = State::from([0x60, 0x70, 0x4d, 0x0c]);

	const TOTAL: u64 = 1u64 << 32;

	let mut hits = 0;
	for i in 0..TOTAL {
		let s = State::from(i as u32);
		let s2 = s ^ delta_input;

		if encrypt(s, &key) == encrypt(s2, &key) ^ delta_output {
			hits += 1;
		}
	}

	println!(
		"Found hits: {}/{} = {}",
		hits,
		TOTAL,
		hits as f32 / TOTAL as f32
	);
}
