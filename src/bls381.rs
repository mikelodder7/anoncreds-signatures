use std::str::FromStr;
use std::num::ParseIntError;
use std::fmt::{Debug, Display, Formatter, Result as FmtResult};
use std::ops::{Add, AddAssign, SubAssign, Mul};

use serde::ser::{Serialize, Serializer};
use serde::de::{Deserialize, Deserializer, Visitor, Error as DError};

use amcl::rand::RAND;
use amcl::bls381::big::BIG;
use amcl::bls381::ecp::ECP;
use amcl::bls381::ecp2::ECP2;
use amcl::bls381::rom;
use amcl::bls381::pair::{g1mul, g2mul, ate, ate2, fexp};
use amcl::bls381::fp12::FP12;

use rand::{Rng, RngCore, thread_rng};
use rand::rngs::ThreadRng;

use digest::Digest;
use digest::generic_array::typenum::{U48, U192, U768};
use zeroize::Zeroize;

use super::*;

lazy_static! {
    static ref G1: ECP = ECP::generator();
    static ref G2: ECP2 = ECP2::generator();
    static ref GROUP_ORDER: GroupOrderElement = GroupOrderElement { value: BIG::new_ints(&rom::CURVE_ORDER) };
}

macro_rules! bytes_impl {
    ($name:ident,$size:ident,$internal:ident) => {
        impl ToBytes for $name {
            type OutputSize = $size;
            fn to_bytes(&self) -> GenericArray<u8, Self::OutputSize> {
                let mut tmp = self.value;
                let mut res = vec![0u8; Self::BYTES_REPR_SIZE];
                tmp.tobytes(&mut res.as_mut_slice());
                let mut out = GenericArray::default();
                out.copy_from_slice(&res);
                out
            }
        }

        from_bytes_impl!($name,$size,$internal);
        from_slice_impl!($name,$internal);
    };
    ($name:ident,$size:ident,$internal:ident,$compress:expr) => {
        impl ToBytes for $name {
            type OutputSize = $size;
            fn to_bytes(&self) -> GenericArray<u8, Self::OutputSize> {
                let mut res = vec![0u8; Self::BYTES_REPR_SIZE];
                self.value.tobytes(&mut res.as_mut_slice(), $compress);
                let mut out = GenericArray::default();
                out.copy_from_slice(&res);
                out
            }
        }

        from_bytes_impl!($name,$size,$internal);
        from_slice_impl!($name,$internal);
    };
}

macro_rules! from_slice_impl {
    ($name:ident,$internal:ident) => {
        impl From<&[u8]> for $name {
            fn from(data: &[u8]) -> Self {
                let mut vec = data.to_vec();
                if data.len() > Self::BYTES_REPR_SIZE {
                    vec = data[0..Self::BYTES_REPR_SIZE].to_vec();
                } else if data.len() < Self::BYTES_REPR_SIZE {
                    let diff = Self::BYTES_REPR_SIZE - data.len();
                    let mut result = vec![0u8; diff];
                    result.append(&mut vec);
                    vec = result;
                }
                $name {
                    value: $internal::frombytes(vec.as_slice())
                }
            }
        }
    };
}
macro_rules! from_bytes_impl {
    ($name:ident,$size:ident,$internal:ident) => {
        impl FromBytes for $name {
            type InputSize = $size;
            fn from_bytes(input: GenericArray<u8, Self::InputSize>) -> Self {
                $name {
                    value: $internal::frombytes(input.as_slice())
                }
            }
        }
    };
}

macro_rules! format_impl {
    ($name:ident) => {
        impl Display for $name {
            fn fmt(&self, f: &mut Formatter) -> FmtResult {
                let mut value = self.value;
                write!(f, "$name( {} )", value.to_hex())
            }
        }

        impl Debug for $name {
            fn fmt(&self, f: &mut Formatter) -> FmtResult {
                let mut value = self.value;
                write!(f, "$name( {} )", value.to_hex())
            }
        }
    };
    ($name:ident, $format:expr) => {
        impl Display for $name {
            fn fmt(&self, f: &mut Formatter) -> FmtResult {
                write!(f, "$name( {} )", self.value.to_hex())
            }
        }

        impl Debug for $name {
            fn fmt(&self, f: &mut Formatter) -> FmtResult {
                write!(f, "$name( {} )", self.value.to_hex())
            }
        }
    };
}

macro_rules! serialize_impl {
    ($name:ident,$internal:ident,$visitor:ident) => {
        impl FromStr for $name {
            type Err = ParseIntError;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                Ok($name {
                    value: $internal::from_hex(s.to_string())
                })
            }
        }

        impl Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error> where S: Serializer {
                serializer.serialize_newtype_struct("$name", &self.to_string())
            }
        }

        impl<'a> Deserialize<'a> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error> where D: Deserializer<'a> {
                struct $visitor;

                impl<'a> Visitor<'a> for $visitor {
                    type Value = $name;

                    fn expecting(&self, formatter: &mut Formatter) -> FmtResult {
                        formatter.write_str("expected $name")
                    }

                    fn visit_str<E>(self, value: &str) -> Result<$name, E>
                        where E: DError
                    {
                        Ok($name::from_str(value).map_err(DError::custom)?)
                    }
                }

                deserializer.deserialize_str($visitor)
            }
        }
    };
}

#[derive(Clone, Eq, PartialEq, Ord, PartialOrd)]
pub struct GroupOrderElement {
    value: BIG
}

impl GroupOrderElement {
    pub const BYTES_REPR_SIZE: usize = rom::MODBYTES;

    pub fn new() -> Self {
        GroupOrderElement { value: random_mod_order::<ThreadRng>(None) }
    }

    pub fn from_rng<R: Rng>(rng: &mut R) -> Self {
        GroupOrderElement { value: random_mod_order(Some(rng)) }
    }

    pub fn from_hash<D: Digest<OutputSize = U48>>(data: &[u8]) -> Self {
        GroupOrderElement { value: hash_mod_order::<D>(data) }
    }

    pub fn mod_mul(&self, rhs: &Self) -> Self {
        GroupOrderElement { value: BIG::modmul(&self.value, &rhs.value, &GROUP_ORDER.value) }
    }

    pub fn mod_neg(&self) -> Self {
        GroupOrderElement { value: BIG::modneg(&self.value, &GROUP_ORDER.value) }
    }

    pub fn mod_inverse(&mut self) {
        self.value.invmodp(&GROUP_ORDER.value);
    }
}

impl Drop for GroupOrderElement {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl Zeroize for GroupOrderElement {
    fn zeroize(&mut self) {
        self.value.w.zeroize();
    }
}

impl Add for GroupOrderElement {
    type Output = GroupOrderElement;

    fn add(self, rhs: Self) -> Self::Output {
        let mut value = BIG::new_big(&self.value);
        value.add(&rhs.value);
        GroupOrderElement { value }
    }
}

impl AddAssign<&GroupOrderElement> for GroupOrderElement {
    fn add_assign(&mut self, rhs: &Self) {
        self.value.add(&rhs.value);
    }
}

impl AddModAssign for GroupOrderElement {
    fn addmod_assign(&mut self, rhs: &Self) {
        self.value.add(&rhs.value);
        self.value.rmod(&GROUP_ORDER.value);
    }
}

impl SubModAssign for GroupOrderElement {
    fn submod_assign(&mut self, rhs: &Self) {
        self.value.sub(&rhs.value);
        self.value.rmod(&GROUP_ORDER.value);
    }
}

impl From<u32> for GroupOrderElement {
    fn from(data: u32) -> GroupOrderElement {
        GroupOrderElement { value: BIG::new_int(data as isize) }
    }
}

bytes_impl!(GroupOrderElement, U48, BIG);
format_impl!(GroupOrderElement);
serialize_impl!(GroupOrderElement, BIG, GroupOrderElementVisitor);

#[derive(Clone, PartialEq)]
pub struct PointG1 {
    value: ECP
}

impl PointG1 {
    pub const BYTES_REPR_SIZE: usize = rom::MODBYTES * 4;

    pub fn new() -> Self {
        PointG1 {
            value: g1mul(&G1, &mut random_mod_order::<ThreadRng>(None))
        }
    }

    pub fn new_infinity() -> Self {
        let mut value = ECP::new();
        value.inf();
        PointG1 {
            value
        }
    }

    pub fn from_rng<R: Rng>(rng: &mut R) -> Self {
        PointG1 {
            value: g1mul(&G1, &mut random_mod_order(Some(rng)))
        }
    }

    pub fn from_hash<D: Digest<OutputSize = U48>>(data: &[u8]) -> Self {
        let n = GroupOrderElement::from_hash::<D>(data);

        let value = ECP::mapit(n.to_bytes().as_slice());

        PointG1 { value }
    }

    pub fn base() -> PointG1 {
        PointG1 { value: ECP::generator() }
    }

    pub fn mul2(p1: &PointG1, v1: &GroupOrderElement, p2: &PointG1, v2: &GroupOrderElement) -> PointG1 {
        PointG1 { value: p1.value.mul2(&v1.value, &p2.value, &v2.value) }
    }

    pub fn is_infinity(&self) -> bool {
        self.value.is_infinity()
    }
}

impl Drop for PointG1 {
    fn drop(&mut self) {
        self.value.inf();
    }
}

impl AddAssign for PointG1 {
    fn add_assign(&mut self, rhs: PointG1) {
        self.value.add(&rhs.value);
    }
}

impl AddAssign<&PointG1> for PointG1 {
    fn add_assign(&mut self, rhs: &PointG1) {
        self.value.add(&rhs.value);
    }
}

impl SubAssign for PointG1 {
    fn sub_assign(&mut self, rhs: PointG1) {
        self.value.sub(&rhs.value);
    }
}

impl Mul<GroupOrderElement> for PointG1 {
    type Output = PointG1;

    fn mul(self, element: GroupOrderElement) -> PointG1 {
        PointG1 { value: self.value.mul(&element.value) }
    }
}

impl<'a, 'b> Mul<&'b GroupOrderElement> for &'a PointG1 {
    type Output = PointG1;

    fn mul(self, rhs: &'b GroupOrderElement) -> PointG1 {
        PointG1 { value: self.value.mul(&rhs.value) }
    }
}

bytes_impl!(PointG1, U192, ECP, false);
format_impl!(PointG1, false);
serialize_impl!(PointG1, ECP, PointG1Visitor);

#[derive(Clone, PartialEq)]
pub struct PointG2 {
    value: ECP2
}

impl PointG2 {
    pub const BYTES_REPR_SIZE: usize = rom::MODBYTES * 4;

    pub fn new() -> Self {
        PointG2 {
            value: g2mul(&G2, &mut random_mod_order::<ThreadRng>(None))
        }
    }

    pub fn new_infinity() -> Self {
        let mut value = ECP2::new();
        value.inf();
        PointG2 {
            value
        }
    }

    pub fn from_rng<R: Rng>(rng: &mut R) -> Self {
        PointG2 {
            value: g2mul(&G2, &mut random_mod_order(Some(rng)))
        }
    }

    pub fn from_scalar(s: &GroupOrderElement) -> Self {
        PointG2 { value: g2mul(&G2, &s.value) }
    }

    pub fn base() -> Self {
        PointG2 { value: ECP2::generator() }
    }

    pub fn is_infinity(&self) -> bool {
        self.value.is_infinity()
    }
}

impl Drop for PointG2 {
    fn drop(&mut self) {
        self.value.inf();
    }
}

impl Add for PointG2 {
    type Output = PointG2;

    fn add(self, rhs: Self::Output) -> Self::Output {
        let mut out = self.clone();
        out.value.add(&rhs.value);
        out
    }
}

impl AddAssign for PointG2 {
    fn add_assign(&mut self, rhs: PointG2) {
        self.value.add(&rhs.value);
    }
}

impl SubAssign for PointG2 {
    fn sub_assign(&mut self, rhs: PointG2) {
        self.value.sub(&rhs.value);
    }
}

impl Mul<GroupOrderElement> for PointG2 {
    type Output = PointG2;

    fn mul(self, rhs: GroupOrderElement) -> PointG2 {
        PointG2 { value: self.value.mul(&rhs.value) }
    }
}

impl<'a, 'b> Mul<&'b GroupOrderElement> for &'a PointG2 {
    type Output = PointG2;

    fn mul(self, rhs: &'b GroupOrderElement) -> PointG2 {
        PointG2 { value: self.value.mul(&rhs.value) }
    }
}

bytes_impl!(PointG2, U192, ECP2);
format_impl!(PointG2, false);
serialize_impl!(PointG2, ECP2, PointG2Visitor);

#[derive(Clone, PartialEq)]
pub struct Pair {
    value: FP12
}

impl Pair {
    pub const BYTES_REPR_SIZE: usize = rom::MODBYTES * 16;

    pub fn pair(p: &PointG1, q: &PointG2) -> Self {
        let mut value = fexp(&ate(&q.value, &p.value));
        value.reduce();

        Pair { value }
    }

    pub fn pair_cmp(p1: &PointG1, q1: &PointG2, p2: &PointG1, q2: &PointG2) -> bool {
        let mut p = p1.value;
        p.neg();
        let value = fexp(&ate2(&q1.value, &p, &q2.value, &p2.value));
        value.isunity()
    }

    pub fn inverse(&mut self) {
        self.value.conj();
    }
}

impl Drop for Pair {
    fn drop(&mut self) {
        self.value.one()
    }
}

bytes_impl!(Pair, U768, FP12);
format_impl!(Pair);
serialize_impl!(Pair, FP12, PairVisitor);

fn hash_mod_order<D: Digest<OutputSize = U48>>(data: &[u8]) -> BIG {
    let result = D::digest(data);
    let mut out = BIG::frombytes(result.as_slice());
    out.rmod(&GROUP_ORDER.value);
    out
}

fn random_mod_order<R: Rng>(r: Option<&mut R>) -> BIG {
    const ENTROPY_BYTES: usize = 128;
    let mut seed = vec![0u8; ENTROPY_BYTES];
    match r {
        Some(rr) => rr.fill_bytes(&mut seed.as_mut_slice()),
        None => thread_rng().fill_bytes(&mut seed.as_mut_slice())
    };
    let mut rng = RAND::new();
    rng.clean();
    rng.seed(ENTROPY_BYTES, &seed.as_slice());
    BIG::randomnum(&GROUP_ORDER.value, &mut rng)
}
