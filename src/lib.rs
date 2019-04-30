#[macro_use]
extern crate lazy_static;

use digest::generic_array::{GenericArray, ArrayLength};

pub trait ToBytes {
    type OutputSize: ArrayLength<u8>;
    fn to_bytes(&self) -> GenericArray<u8, Self::OutputSize>;
}

pub trait FromBytes {
    type InputSize: ArrayLength<u8>;
    fn from_bytes(input: GenericArray<u8, Self::InputSize>) -> Self;
}

pub trait PowMod<RHS = Self> {
    type Output;
    fn powmod(&self, e: &RHS) -> Self::Output;
}

pub trait PowModAssign<RHS = Self> {
    fn powmod(&mut self, e: &RHS);
}

pub trait AddMod<RHS = Self> {
    type Output;
    fn addmod(&self, r: &RHS) -> Self::Output;
}

pub trait AddModAssign<RHS = Self> {
    fn addmod_assign(&mut self, r: &RHS);
}

pub trait SubModAssign<RHS = Self> {
    fn submod_assign(&mut self, r: &RHS);
}

#[macro_use]
mod macros;
pub mod bls381;
pub mod bn254;
pub mod bbs;
