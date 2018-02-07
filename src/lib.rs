#![warn(missing_docs)]
#![doc(html_root_url = "https://docs.rs/ipcrypt/0.1.0")]

//! `ipcrypt` was designed by Jean-Philippe Aumasson to encrypt IPv4
//! addresses with 16-byte keys, where the result is still an IPv4
//! address.
//!
//! Derived from the implementation at: <https://github.com/veorq/ipcrypt>
//!
//! As input and output this implementation takes various types
//! representing a sequence of 4 bytes.  `u32` is interpreted as big
//! endian (network order; for consistency with how IPv4 adresses are
//! represented as `u32`).
//!
//! This crate supports a `no-std` feature which removes support for
//! `Ipv4Addr` (because it's not available in `core`).
//!
//! # Example
//!
//! ```
//! use std::net::Ipv4Addr;
//! let addr = "127.0.0.1".parse::<Ipv4Addr>().unwrap();
//! println!("{}", ipcrypt::encrypt(addr, b"some 16-byte key"));
//! ```

#![cfg_attr(feature = "no-std", no_std)]
#![no_implicit_prelude]

#[cfg(not(feature = "no-std"))]
extern crate core;

#[cfg(not(feature = "no-std"))]
use std::net::Ipv4Addr;

use core::convert::{From, Into};
use core::ops::BitXorAssign;

/// Alias for the key type (16 bytes)
pub type Key = [u8; 16];

/// The inner state permutations are build on.  Input and Output types
/// are converted to an from this type.
///
/// You could provide custom `From` and `Into` implementations for local
/// types, and then use [`encrypt`] and [`decrypt`] directly on those
/// types.
///
/// [`encrypt`]: fn.encrypt.html
/// [`decrypt`]: fn.decrypt.html
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct State(u8, u8, u8, u8);

impl State {
	fn encrypt(mut self, key: &Key) -> Self {
		let KeyStates(a, b, c, d) = KeyStates::from(key);

		self ^= a;
		self = self.permute();
		self ^= b;
		self = self.permute();
		self ^= c;
		self = self.permute();
		self ^= d;

		self
	}

	fn decrypt(mut self, key: &Key) -> Self {
		let KeyStates(a, b, c, d) = KeyStates::from(key);

		self ^= d;
		self = self.permute_inverse();
		self ^= c;
		self = self.permute_inverse();
		self ^= b;
		self = self.permute_inverse();
		self ^= a;

		self
	}

	fn permute(self) -> Self {
		let State(mut a, mut b, mut c, mut d) = self;

		a = a.wrapping_add(b);
		c = c.wrapping_add(d);
		b = b.rotate_left(2);
		d = d.rotate_left(5);
		b ^= a;
		d ^= c;
		a = a.rotate_left(4);
		a = a.wrapping_add(d);
		c = c.wrapping_add(b);
		b = b.rotate_left(3);
		d = d.rotate_left(7);
		b ^= c;
		d ^= a;
		c = c.rotate_left(4);

		State(a, b, c, d)
	}

	fn permute_inverse(self) -> Self {
		let State(mut a, mut b, mut c, mut d) = self;

		c = c.rotate_left(4);
		b ^= c;
		d ^= a;
		b = b.rotate_left(5);
		d = d.rotate_left(1);
		a = a.wrapping_sub(d);
		c = c.wrapping_sub(b);
		a = a.rotate_left(4);
		b ^= a;
		d ^= c;
		b = b.rotate_left(6);
		d = d.rotate_left(3);
		a = a.wrapping_sub(b);
		c = c.wrapping_sub(d);

		State(a, b, c, d)
	}
}

impl From<[u8; 4]> for State {
	#[inline(always)]
	fn from(v: [u8; 4]) -> Self {
		State(v[0], v[1], v[2], v[3])
	}
}

impl Into<[u8; 4]> for State {
	#[inline(always)]
	fn into(self) -> [u8; 4] {
		let State(a, b, c, d) = self;
		[a, b, c, d]
	}
}

#[cfg(not(feature = "no-std"))]
impl From<Ipv4Addr> for State {
	#[inline(always)]
	fn from(ip: Ipv4Addr) -> Self {
		let o = ip.octets();
		State(o[0], o[1], o[2], o[3])
	}
}

#[cfg(not(feature = "no-std"))]
impl Into<Ipv4Addr> for State {
	#[inline(always)]
	fn into(self) -> Ipv4Addr {
		let octets: [u8; 4] = self.into();
		octets.into()
	}
}

impl From<u32> for State {
	#[inline(always)]
	fn from(v: u32) -> Self {
		let (a, b, c, d) =
			((v >> 24) as u8, (v >> 16) as u8, (v >> 8) as u8, v as u8);
		State(a, b, c, d)
	}
}

impl Into<u32> for State {
	#[inline(always)]
	fn into(self) -> u32 {
		let State(a, b, c, d) = self;
		((a as u32) << 24) | ((b as u32) << 16) | ((c as u32) << 8) | (d as u32)
	}
}

impl BitXorAssign for State {
	#[inline(always)]
	fn bitxor_assign(&mut self, rhs: State) {
		self.0 ^= rhs.0;
		self.1 ^= rhs.1;
		self.2 ^= rhs.2;
		self.3 ^= rhs.3;
	}
}

/// Represents 16-byte key (which is internally read as 4 `State`s).
#[derive(Clone, Copy, PartialEq, Eq)]
struct KeyStates(State, State, State, State);

impl<'a> From<&'a Key> for KeyStates {
	fn from(key: &'a Key) -> KeyStates {
		KeyStates(
			State(key[0], key[1], key[2], key[3]),
			State(key[4], key[5], key[6], key[7]),
			State(key[8], key[9], key[10], key[11]),
			State(key[12], key[13], key[14], key[15]),
		)
	}
}

/// Encrypt value with given key.
///
/// # Example
///
/// ```
/// use std::net::Ipv4Addr;
/// let addr = "127.0.0.1".parse::<Ipv4Addr>().unwrap();
/// println!("{}", ipcrypt::encrypt(addr, b"some 16-byte key"));
/// ```
pub fn encrypt<T>(v: T, key: &Key) -> T
where
	State: From<T> + Into<T>,
{
	State::from(v).encrypt(key).into()
}

/// Decrypt value with given key.
///
/// # Example
///
/// ```
/// use std::net::Ipv4Addr;
/// let addr = "114.62.227.59".parse::<Ipv4Addr>().unwrap();
/// println!("{}", ipcrypt::decrypt(addr, b"some 16-byte key"));
/// ```
pub fn decrypt<T>(v: T, key: &Key) -> T
where
	State: From<T> + Into<T>,
{
	State::from(v).decrypt(key).into()
}

#[cfg(test)]
#[cfg(not(feature = "no-std"))]
mod test {
	use {decrypt, encrypt, Key};
	use std::net::Ipv4Addr;

	fn check_addr(key: &Key, plain: Ipv4Addr, cipher: Ipv4Addr) {
		assert_eq!(encrypt(plain, key), cipher);

		assert_eq!(decrypt(cipher, key), plain);
	}

	fn check(key: &Key, plain: &str, cipher: &str) {
		let plain = plain.parse::<Ipv4Addr>().unwrap();
		let cipher = cipher.parse::<Ipv4Addr>().unwrap();
		check_addr(key, plain, cipher);
	}

	static KEY: &Key = b"some 16-byte key";

	#[test]
	fn test_a() {
		check(KEY, "127.0.0.1", "114.62.227.59");
	}

	#[test]
	fn test_b() {
		check(KEY, "8.8.8.8", "46.48.51.50");
	}

	#[test]
	fn test_c() {
		check(KEY, "1.2.3.4", "171.238.15.199");
	}
}

#[cfg(test)]
mod test_raw {
	use {decrypt, encrypt, Key};

	fn check(key: &Key, plain: [u8; 4], cipher: [u8; 4]) {
		assert_eq!(encrypt(plain, key), cipher);

		assert_eq!(decrypt(cipher, key), plain);
	}

	static KEY: &Key = b"some 16-byte key";

	#[test]
	fn test_a() {
		check(KEY, [127, 0, 0, 1], [114, 62, 227, 59]);
	}

	#[test]
	fn test_b() {
		check(KEY, [8, 8, 8, 8], [46, 48, 51, 50]);
	}

	#[test]
	fn test_c() {
		check(KEY, [1, 2, 3, 4], [171, 238, 15, 199]);
	}
}
