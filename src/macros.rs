macro_rules! group_order_element_impl {
    ($big:ident, $size:ident, $rom:ident) => {
        #[derive(Clone, Eq, PartialEq, Ord, PartialOrd)]
        pub struct GroupOrderElement {
            value: $big
        }

        impl GroupOrderElement {
            pub const BYTES_REPR_SIZE: usize = $rom::MODBYTES;

            pub fn new() -> Self {
                GroupOrderElement { value: random_mod_order::<ThreadRng>(None) }
            }

            pub fn from_rng<R: Rng>(rng: &mut R) -> Self {
                GroupOrderElement { value: random_mod_order(Some(rng)) }
            }

            pub fn from_hash<D: Digest<OutputSize = $size>>(data: &[u8]) -> Self {
                GroupOrderElement { value: hash_mod_order::<D>(data) }
            }

            pub fn mod_neg(&self) -> Self {
                GroupOrderElement { value: $big::modneg(&self.value, &GROUP_ORDER.value) }
            }

            pub fn mod_inverse(&mut self) {
                self.value.invmodp(&GROUP_ORDER.value);
            }

            fn repr_bytes(&self, res: &mut Vec<u8>) {
                let mut tmp = self.value;
                tmp.tobytes(&mut res.as_mut_slice());
            }

            fn to_hex(&self) -> String {
                let mut tmp = self.value;
                tmp.to_hex()
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

            fn add(self, rhs: Self::Output) -> Self::Output {
                let mut value = $big::new_big(&self.value);
                value.add(&rhs.value);
                value.rmod(&GROUP_ORDER.value);
                GroupOrderElement { value }
            }
        }

        impl<'a, 'b> Add<&'b GroupOrderElement> for &'a GroupOrderElement {
            type Output = GroupOrderElement;

            fn add(self, rhs: &'b Self::Output) -> Self::Output {
                let mut value = $big::new_big(&self.value);
                value.add(&rhs.value);
                value.rmod(&GROUP_ORDER.value);
                GroupOrderElement { value }
            }
        }

        impl AddAssign<&GroupOrderElement> for GroupOrderElement {
            fn add_assign(&mut self, rhs: &Self) {
                self.value.add(&rhs.value);
                self.value.rmod(&GROUP_ORDER.value);
            }
        }

        impl Sub for GroupOrderElement {
            type Output = GroupOrderElement;

            fn sub(self, rhs: Self::Output) -> Self::Output {
                let mut value = $big::new_big(&self.value);
                value.sub(&rhs.value);

                if value < $big::new() {
                    value = $big::modneg(&value, &GROUP_ORDER.value);
                }
                GroupOrderElement { value }
            }
        }

        impl<'a, 'b> Sub<&'b GroupOrderElement> for &'a GroupOrderElement {
            type Output = GroupOrderElement;

            fn sub(self, rhs: &'b Self::Output) -> Self::Output {
                let mut value = $big::new_big(&self.value);
                value.sub(&rhs.value);

                if value < $big::new() {
                    value = $big::modneg(&value, &GROUP_ORDER.value);
                }
                GroupOrderElement { value }
            }
        }

        impl SubAssign<&GroupOrderElement> for GroupOrderElement {
            fn sub_assign(&mut self, rhs: &Self) {
                self.value.sub(&rhs.value);
                if self.value < $big::new() {
                    self.value = $big::modneg(&self.value, &GROUP_ORDER.value);
                }
            }
        }

        impl Mul for GroupOrderElement {
            type Output = GroupOrderElement;

            fn mul(self, element: GroupOrderElement) -> Self::Output {
                GroupOrderElement { value: $big::modmul(&self.value, &element.value, &GROUP_ORDER.value) }
            }
        }

        impl<'a, 'b> Mul<&'b GroupOrderElement> for &'a GroupOrderElement {
            type Output = GroupOrderElement;

            fn mul(self, element: &'b GroupOrderElement) -> Self::Output {
                GroupOrderElement { value: $big::modmul(&self.value, &element.value, &GROUP_ORDER.value) }
            }
        }

        impl From<u32> for GroupOrderElement {
            fn from(data: u32) -> GroupOrderElement {
                GroupOrderElement { value: $big::new_int(data as isize) }
            }
        }

        bytes_impl!(GroupOrderElement, $size, $big);
        format_impl!(GroupOrderElement);
        serialize_impl!(GroupOrderElement, $big, GroupOrderElementVisitor);
    };
}

macro_rules! pointg1_impl {
    ($point:ident, $size:ident, $group_size:ident, $rom:ident) => {
        #[derive(Clone, PartialEq)]
        pub struct PointG1 {
            value: $point
        }

        impl PointG1 {
            pub const BYTES_REPR_SIZE: usize = $rom::MODBYTES * 4;

            pub fn new() -> Self {
                PointG1 {
                    value: G1.mul(&mut random_mod_order::<ThreadRng>(None))
                }
            }

            pub fn new_infinity() -> Self {
                let mut value = $point::new();
                value.inf();
                PointG1 {
                    value
                }
            }

            pub fn from_rng<R: Rng>(rng: &mut R) -> Self {
                PointG1 {
                    value: G1.mul(&mut random_mod_order(Some(rng)))
                }
            }

            pub fn from_hash<D: Digest<OutputSize = $group_size>>(data: &[u8]) -> Self {
                let n = GroupOrderElement::from_hash::<D>(data);

                let value = $point::mapit(n.to_bytes().as_slice());

                PointG1 { value }
            }

            pub fn base() -> PointG1 {
                PointG1 { value: $point::generator() }
            }

            pub fn mul2(p1: &PointG1, v1: &GroupOrderElement, p2: &PointG1, v2: &GroupOrderElement) -> PointG1 {
                PointG1 { value: p1.value.mul2(&v1.value, &p2.value, &v2.value) }
            }

            pub fn is_infinity(&self) -> bool {
                self.value.is_infinity()
            }

            fn repr_bytes(&self, res: &mut Vec<u8>) {
                self.value.tobytes(&mut res.as_mut_slice(), false);
            }

            fn to_hex(&self) -> String {
                self.value.to_hex()
            }
        }

        impl Drop for PointG1 {
            fn drop(&mut self) {
                self.value.inf();
            }
        }

        impl Add for PointG1 {
            type Output = PointG1;

            fn add(self, rhs: Self::Output) -> Self::Output {
                let mut value = self.clone();
                value.value.add(&rhs.value);
                value
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

        impl Sub for PointG1 {
            type Output = PointG1;

            fn sub(self, rhs: Self::Output) -> Self::Output {
                let mut value = self.clone();
                value.value.sub(&rhs.value);
                value
            }
        }

        impl<'a, 'b> Sub<&'b PointG1> for &'a PointG1 {
            type Output = PointG1;

            fn sub(self, rhs: &'b PointG1) -> Self::Output {
                let mut value = self.clone();
                value.value.sub(&rhs.value);
                value
            }
        }

        impl SubAssign for PointG1 {
            fn sub_assign(&mut self, rhs: PointG1) {
                self.value.sub(&rhs.value);
            }
        }

        impl Mul<GroupOrderElement> for PointG1 {
            type Output = PointG1;

            fn mul(self, element: GroupOrderElement) -> Self::Output {
                PointG1 { value: self.value.mul(&element.value) }
            }
        }

        impl<'a, 'b> Mul<&'b GroupOrderElement> for &'a PointG1 {
            type Output = PointG1;

            fn mul(self, rhs: &'b GroupOrderElement) -> Self::Output {
                PointG1 { value: self.value.mul(&rhs.value) }
            }
        }

        bytes_impl!(PointG1, $size, $point);
        format_impl!(PointG1);
        serialize_impl!(PointG1, $point, PointG1Visitor);
    };
}

macro_rules! pointg2_impl {
    ($point:ident, $size:ident, $rom:ident) => {
        #[derive(Clone, PartialEq)]
        pub struct PointG2 {
            value: $point
        }

        impl PointG2 {
            pub const BYTES_REPR_SIZE: usize = $rom::MODBYTES * 4;

            pub fn new() -> Self {
                PointG2 {
                    value: G2.mul(&mut random_mod_order::<ThreadRng>(None))
                }
            }

            pub fn new_infinity() -> Self {
                let mut value = $point::new();
                value.inf();
                PointG2 {
                    value
                }
            }

            pub fn from_rng<R: Rng>(rng: &mut R) -> Self {
                PointG2 {
                    value: G2.mul(&mut random_mod_order(Some(rng)))
                }
            }

            pub fn from_scalar(s: &GroupOrderElement) -> Self {
                PointG2 { value: G2.mul(&s.value) }
            }

            pub fn base() -> Self {
                PointG2 { value: $point::generator() }
            }

            pub fn is_infinity(&self) -> bool {
                self.value.is_infinity()
            }

            fn repr_bytes(&self, res: &mut Vec<u8>) {
                self.value.tobytes(&mut res.as_mut_slice());
            }

            fn to_hex(&self) -> String {
                self.value.to_hex()
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

        bytes_impl!(PointG2, $size, $point);
        format_impl!(PointG2);
        serialize_impl!(PointG2, $point, PointG2Visitor);

    };
}

macro_rules! pair_impl  {
    ($pair:ident, $size:ident, $fexp:ident, $ate:ident, $ate2:ident, $rom:ident) => {
        #[derive(Clone, PartialEq)]
        pub struct Pair {
            value: $pair
        }

        impl Pair {
            pub const BYTES_REPR_SIZE: usize = $rom::MODBYTES * 16;

            pub fn pair(p: &PointG1, q: &PointG2) -> Self {
                let mut value = $fexp(&$ate(&q.value, &p.value));
                value.reduce();

                Pair { value }
            }

            pub fn pair_cmp(p1: &PointG1, q1: &PointG2, p2: &PointG1, q2: &PointG2) -> bool {
                let mut p = p1.value;
                p.neg();
                let value = $fexp(&$ate2(&q1.value, &p, &q2.value, &p2.value));
                value.isunity()
            }

            pub fn inverse(&mut self) {
                self.value.conj();
            }

            fn repr_bytes(&self, res: &mut Vec<u8>) {
                let mut tmp = self.value;
                tmp.tobytes(&mut res.as_mut_slice());
            }

            fn to_hex(&self) -> String {
                self.value.to_hex()
            }
        }

        impl Drop for Pair {
            fn drop(&mut self) {
                self.value.one()
            }
        }

        bytes_impl!(Pair, $size, $pair);
        format_impl!(Pair);
        serialize_impl!(Pair, $pair, PairVisitor);
    };
}

macro_rules! bytes_impl {
    ($name:ident,$size:ident,$internal:ident) => {
        impl ToBytes for $name {
            type OutputSize = $size;
            fn to_bytes(&self) -> GenericArray<u8, Self::OutputSize> {
                let mut res = vec![0u8; Self::BYTES_REPR_SIZE];
                self.repr_bytes(&mut res);
                let mut out = GenericArray::default();
                out.copy_from_slice(&res);
                out
            }
        }

        impl FromBytes for $name {
            type InputSize = $size;
            fn from_bytes(input: GenericArray<u8, Self::InputSize>) -> Self {
                $name {
                    value: $internal::frombytes(input.as_slice())
                }
            }
        }

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

macro_rules! format_impl {
    ($name:ident) => {
        impl Display for $name {
            fn fmt(&self, f: &mut Formatter) -> FmtResult {
                write!(f, "$name( {} )", self.to_hex())
            }
        }

        impl Debug for $name {
            fn fmt(&self, f: &mut Formatter) -> FmtResult {
                write!(f, "$name( {} )", self.to_hex())
            }
        }
    };
}

macro_rules! serialize_impl {
    ($name:ident, $internal:ident, $visitor:ident) => {
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

macro_rules! hash_mod_order {
    ($big:ident, $size:ident) => {
        fn hash_mod_order<D: Digest<OutputSize = $size>>(data: &[u8]) -> $big {
            let result = D::digest(data);
            let mut out = $big::frombytes(result.as_slice());
            out.rmod(&GROUP_ORDER.value);
            out
        }
    };
}

macro_rules! random_mod_order {
    ($big:ident, $rom:ident) => {
        fn random_mod_order<R: Rng>(r: Option<&mut R>) -> $big {
            let mut seed = vec![0u8; $rom::MODBYTES];
            match r {
                Some(rr) => rr.fill_bytes(&mut seed.as_mut_slice()),
                None => thread_rng().fill_bytes(&mut seed.as_mut_slice())
            };
            let mut res = $big::frombytes(seed.as_slice());
            res.rmod(&GROUP_ORDER.value);
            res
        }
    };
}

macro_rules! curve {
    ($name:ident, $bytes_group_order:ident, $bytes_points:ident, $bytes_pair:ident) => {
use std::str::FromStr;
use std::num::ParseIntError;
use std::fmt::{Debug, Display, Formatter, Result as FmtResult};
use std::ops::{Add, AddAssign, Sub, SubAssign, Mul};

use serde::ser::{Serialize, Serializer};
use serde::de::{Deserialize, Deserializer, Visitor, Error as DError};

use amcl::$name::big::BIG;
use amcl::$name::ecp::ECP;
use amcl::$name::ecp2::ECP2;
use amcl::$name::rom;
use amcl::$name::pair::{ate, ate2, fexp};
use amcl::$name::fp12::FP12;

use rand::{Rng, RngCore, thread_rng};
use rand::rngs::ThreadRng;

use digest::Digest;
use zeroize::Zeroize;

lazy_static! {
    static ref G1: ECP = ECP::generator();
    static ref G2: ECP2 = ECP2::generator();
    static ref GROUP_ORDER: GroupOrderElement = GroupOrderElement { value: BIG::new_ints(&rom::CURVE_ORDER) };
}

group_order_element_impl!(BIG, $bytes_group_order, rom);
pointg1_impl!(ECP, $bytes_points, $bytes_group_order, rom);
pointg2_impl!(ECP2, $bytes_points, rom);
pair_impl!(FP12, $bytes_pair, fexp, ate, ate2, rom);
hash_mod_order!(BIG, $bytes_group_order);
random_mod_order!(BIG, rom);

    };
}
