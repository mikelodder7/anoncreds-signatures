use crate::bls381::*;
//use crate::bn254::*;
use crate::ToBytes;

use serde::{Serialize, Deserialize};

use rand::{Rng, thread_rng};

use std::collections::{HashSet, HashMap};
use std::iter::FromIterator;

const CONTEXT_BYTES: usize = 16;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PublicKey {
    h0: PointG1,      //blinding factor base
    h: Vec<PointG1>,  //base for each message to be signed
    w: PointG2        //commitment to private key
}

impl PublicKey {
    pub fn generate(attributes: usize, sk: &SecretKey) -> PublicKey {
        let w = PointG2::from_scalar(&sk);
        let mut h = Vec::with_capacity(attributes);
        for _ in 0..attributes {
            h.push(PointG1::new());
        }

        let h0 = PointG1::new();
        PublicKey { h0, w, h }
    }

    pub fn well_formed(&self) -> bool {
        self.h.iter().all(|v| !v.is_infinity()) &&
        !self.w.is_infinity() &&
        !self.h0.is_infinity()
    }

    pub fn attributes(&self) -> usize {
        self.h.len()
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(PointG2::BYTES_REPR_SIZE + PointG1::BYTES_REPR_SIZE * (self.h.len() + 1) + 4);
        out.extend_from_slice(self.w.to_bytes().as_slice());
        out.extend_from_slice(self.h0.to_bytes().as_slice());
        out.extend_from_slice(&(self.h.len() as u32).to_be_bytes());
        for point in &self.h {
            out.extend_from_slice(point.to_bytes().as_slice());
        }
        out
    }

    pub fn verify(&self, signature: &Signature, attributes: &[GroupOrderElement]) -> bool {
        if attributes.len() != self.attributes() {
            return false;
        }
        let b = compute_b(&PointG1::new_infinity(), &self, attributes, &signature.s, 0);
        verify_signature(&b, &signature, &self)
    }
}

impl From<&[u8]> for PublicKey {
    fn from(data: &[u8]) -> Self {
        let mut index = 0;
        let w = PointG2::from(&data[0..PointG2::BYTES_REPR_SIZE]);
        index += PointG2::BYTES_REPR_SIZE;
        let h0 = PointG1::from(&data[index..(index+PointG1::BYTES_REPR_SIZE)]);
        index += PointG1::BYTES_REPR_SIZE;
        let h_size = u32::from_be_bytes([data[index], data[index+1], data[index+2], data[index+3]]) as usize;
        let mut h = Vec::with_capacity(h_size);
        index += 4;
        for _ in 0..h_size {
            let p = PointG1::from(&data[index..(index+PointG1::BYTES_REPR_SIZE)]);
            h.push(p);
            index += PointG1::BYTES_REPR_SIZE;
        }
        PublicKey { w, h0, h }
    }
}

pub type SecretKey = GroupOrderElement;

pub struct KeyPair {
    pub public_key: PublicKey,
    pub secret_key: SecretKey
}

impl KeyPair {
    pub fn generate(attributes: usize) -> Self {
        let secret_key = SecretKey::new();

        KeyPair {
            public_key: PublicKey::generate(attributes, &secret_key),
            secret_key
        }
    }

    pub fn sign(&self, attributes: &[GroupOrderElement]) -> Result<Signature, String> {
        if attributes.len() != self.public_key.attributes() {
            return Err(format!("Expected {} attributes, found {}", self.public_key.attributes(), attributes.len()));
        }

        let e = GroupOrderElement::new();
        let s = GroupOrderElement::new();

        let b = compute_b(&PointG1::new_infinity(), &self.public_key, attributes, &s, 0);
        let mut exp = self.secret_key.clone();
        exp += &e;
        exp.mod_inverse();
        let a = b * exp;

        Ok(Signature { a, e, s })
    }

    pub fn verify(&self, signature: &Signature, attributes: &[GroupOrderElement]) -> bool {
        self.public_key.verify(signature, attributes)
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(self.secret_key.to_bytes().as_slice());
        let mut pk = self.public_key.to_bytes();
        out.append(&mut pk);
        out
    }
}

impl From<&[u8]> for KeyPair {
    fn from(data: &[u8]) -> Self {
        let secret_key = SecretKey::from(&data[0..SecretKey::BYTES_REPR_SIZE]);
        let public_key = PublicKey::from(&data[SecretKey::BYTES_REPR_SIZE..]);
        KeyPair { public_key, secret_key }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct KeyCorrectnessProof {
    c: GroupOrderElement,
    s: GroupOrderElement,
    bar_g1: PointG1,
    bar_g2: PointG1
}

impl KeyCorrectnessProof {
    pub fn generate(key_pair: &KeyPair) -> Self {
        let bar_g1 = PointG1::new();
        let bar_g2 = &bar_g1 * &key_pair.secret_key;

        // ZKP of the secret key which is in W and BarG2.
        let r = GroupOrderElement::new();
        let g2 = PointG2::base();
        let t1 = &g2 * &r; // t1 = g_2^r
        let t2 = &bar_g1 * &r; // t2 = (bar_g_1)^r

        let c = KeyCorrectnessProof::compute_challenge_hash(&t1, &t2, &bar_g1, &bar_g2, &key_pair.public_key.w);
        let s = r + &c * &key_pair.secret_key;
        KeyCorrectnessProof { c, s, bar_g1, bar_g2 }
    }

    pub fn verify(&self, public_key: &PublicKey) -> bool {
        if self.bar_g1.is_infinity() ||
           self.bar_g2.is_infinity() {
            return false;
        }

        let g2 = PointG2::base();
        // t1 = g_2^s * w^{-c}
        let mut t1 = &g2 * &self.s;

        t1 -= &public_key.w * &self.c;

        // t2 = bar_g_1^s * bar_g_2^-c
        let mut t2 = &self.bar_g1 * &self.s;
        t2 -= &self.bar_g2 * &self.c;

        //Verify proof
        let c = KeyCorrectnessProof::compute_challenge_hash(&t1, &t2, &self.bar_g1, &self.bar_g2, &public_key.w);
        c == self.c
    }

    fn compute_challenge_hash(t1: &PointG2,
                              t2: &PointG1,
                              bar_g1: &PointG1,
                              bar_g2: &PointG1,
                              w: &PointG2) -> GroupOrderElement {
        let mut c = Vec::with_capacity(PointG2::BYTES_REPR_SIZE * 3 + PointG1::BYTES_REPR_SIZE * 3);
        c.extend_from_slice(t1.to_bytes().as_slice());
        c.extend_from_slice(t2.to_bytes().as_slice());
        c.extend_from_slice(PointG2::base().to_bytes().as_slice());
        c.extend_from_slice(bar_g1.to_bytes().as_slice());
        c.extend_from_slice(bar_g2.to_bytes().as_slice());
        c.extend_from_slice(w.to_bytes().as_slice());

        GroupOrderElement::from_hash::<sha2::Sha384>(c.as_slice())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Signature {
    a: PointG1,
    e: GroupOrderElement,
    s: GroupOrderElement
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SignatureProtocol {
    label: String,
    state: SignatureTranscript
}

#[derive(Debug, Serialize, Deserialize)]
pub enum SignatureTranscript {
    Offer(SignatureOffer),
    Request(SignatureRequest),
    Issued(SignatureIssue),
    Completed
}

impl SignatureProtocol {
    pub fn new(label: &str) -> SignatureProtocol {
        SignatureProtocol::from_rng(label,&mut thread_rng())
    }

    pub fn from_rng<R: Rng>(label: &str, rng: &mut R) -> SignatureProtocol {
        let mut context = [0u8;  CONTEXT_BYTES];
        rng.fill_bytes(&mut context);
        SignatureProtocol { label: label.to_string(), state: SignatureTranscript::Offer(SignatureOffer { context }) }
    }

    pub fn blind_attributes(&mut self, public_key: &PublicKey, attributes: &[GroupOrderElement]) -> Result<SignatureBlindingFactor, String> {
        let nonce;
        match &self.state {
            SignatureTranscript::Offer(ref context) => nonce = context,
            _ => return Err("blind_attributes can only be called when the transcript is an offer".to_string())
        };

        if attributes.len() > public_key.h.len() {
            return Err("Invalid number of attributes supplied".to_string());
        }

        let mut u = PointG1::new_infinity();
        let mut t = PointG1::new_infinity();
        let s = SignatureBlindingFactor::new();
        let mut s_challenge = GroupOrderElement::new();
        let mut attribute_challenges = Vec::with_capacity(attributes.len());

        let mut i = 0;

        while i + 1 < attributes.len() {
            let v1 = &attributes[i];
            let v2 = &attributes[i + 1];

            let p1 = &public_key.h[i];;
            let p2 = &public_key.h[i + 1];

            u += PointG1::mul2(p1, v1, p2, v2);

            let challenge1 = GroupOrderElement::new();
            let challenge2 = GroupOrderElement::new();

            t += PointG1::mul2(p1, &challenge1, p2, &challenge2);

            i += 2;
            attribute_challenges.push(challenge1);
            attribute_challenges.push(challenge2);
        }

        if i < attributes.len() {
            let p = &public_key.h[i];
            let challenge = GroupOrderElement::new();

            u += PointG1::mul2(p, &attributes[i], &public_key.h0, &s);
            t += PointG1::mul2(p, &challenge, &public_key.h0, &s_challenge);

            attribute_challenges.push(challenge);
        } else {
            u += &public_key.h0 * &s;
            t += &public_key.h0 * &s_challenge;
        }

        let mut challenge_bytes = Vec::new();
        challenge_bytes.extend_from_slice(self.label.as_bytes());
        challenge_bytes.extend_from_slice(&nonce.context);
        challenge_bytes.extend_from_slice(u.to_bytes().as_slice());
        challenge_bytes.extend_from_slice(t.to_bytes().as_slice());
        let hash_challenge = GroupOrderElement::from_hash::<sha2::Sha384>(challenge_bytes.as_slice());

        s_challenge += &(&hash_challenge * &s);
        for i in 0..attribute_challenges.len() {
            attribute_challenges[i] += &(&hash_challenge * &attributes[i]);
        }
        let correctness_proof = SignatureBlindingCorrectnessProof { hash_challenge, s_challenge, attribute_challenges };
        let req = SignatureRequest { u, context: nonce.context, correctness_proof };
        self.state = SignatureTranscript::Request(req);
        Ok(s)
    }

    pub fn issue_signature(&mut self, key_pair: &KeyPair, attributes: &[GroupOrderElement]) -> Result<(), String> {
        let request;
        match &self.state {
            SignatureTranscript::Request(ref req) => request = req,
            _ => return Err("issue_signature can only be called when the transcript is a request".to_string())
        };

        if !SignatureProtocol::verify_correctness_proof(&self.label,
                                                       &key_pair.public_key,
                                                       &request) {
            return Err("Invalid correctness proof".to_string());
        }

        if request.correctness_proof.attribute_challenges.len() + attributes.len() != key_pair.public_key.h.len() {
            return Err("Incorrect number of supplied attributes".to_string());
        }

        let e = GroupOrderElement::new();
        let s = GroupOrderElement::new();

        let b = compute_b(&request.u, &key_pair.public_key, attributes, &s, request.correctness_proof.attribute_challenges.len());

        let mut exp = key_pair.secret_key.clone();
        exp += &e;
        exp.mod_inverse();

        let a = &b * &exp;

        let signature = Signature {
            a, e, s
        };
        self.state = SignatureTranscript::Issued(SignatureIssue { u: request.u.clone(), b, signature });

        Ok(())
    }

    pub fn complete_signature(&mut self, public_key: &PublicKey, s: &SignatureBlindingFactor, attributes: &[GroupOrderElement]) -> Result<Signature, String> {
        let issue;
        match &self.state {
            SignatureTranscript::Issued(ref i) => issue = i,
            _ => return Err("complete_signature can only be called when the transcript is issued".to_string())
        };

        let b = compute_b(&issue.u, public_key, attributes, &issue.signature.s, public_key.h.len() - attributes.len());

        if b != issue.b {
            return Err("Invalid signature: b value".to_string());
        }

        if !verify_signature(&b, &issue.signature, &public_key) {
            return Err("Invalid issued signature".to_string());
        }

        let mut signature = issue.signature.clone();
        signature.s += &s;
        self.state = SignatureTranscript::Completed;
        Ok(signature)
    }

    fn verify_correctness_proof(label: &str, public_key: &PublicKey, request: &SignatureRequest) -> bool {
        let mut u_challenge = PointG1::new_infinity();
        u_challenge += &public_key.h0 * &request.correctness_proof.s_challenge;

        for i in 0..request.correctness_proof.attribute_challenges.len() {
            u_challenge += &public_key.h[i] * &request.correctness_proof.attribute_challenges[i];
        }

        u_challenge += &request.u * &request.correctness_proof.hash_challenge.mod_neg();

        let mut challenge_bytes = Vec::new();
        challenge_bytes.extend_from_slice(label.as_bytes());
        challenge_bytes.extend_from_slice(&request.context);
        challenge_bytes.extend_from_slice(request.u.to_bytes().as_slice());
        challenge_bytes.extend_from_slice(u_challenge.to_bytes().as_slice());

        request.correctness_proof.hash_challenge == GroupOrderElement::from_hash::<sha2::Sha384>(challenge_bytes.as_slice())
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SignatureOffer {
    context: [u8; CONTEXT_BYTES]
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SignatureRequest {
    u: PointG1,
    context: [u8; CONTEXT_BYTES],
    correctness_proof: SignatureBlindingCorrectnessProof
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SignatureBlindingCorrectnessProof {
    hash_challenge: GroupOrderElement,
    s_challenge: GroupOrderElement,
    attribute_challenges: Vec<GroupOrderElement>
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SignatureIssue {
    signature: Signature,
    b: PointG1,
    u: PointG1
}

pub type SignatureBlindingFactor = GroupOrderElement;

#[derive(Debug, Serialize, Deserialize)]
pub enum ProofTranscript {
    Request(ProofRequest),
    Fulfilled(Proof),
    Verified
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ProofRequest {
    disclosed_attributes: HashSet<usize>
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Proof {
    hash_challenge: GroupOrderElement,
    r: ProofR,
    p: ProofP
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ProofR {
    a_prime: PointG1,
    a_bar: PointG1,
    d: PointG1,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ProofP {
    e_challenge: GroupOrderElement,
    r2_challenge: GroupOrderElement,
    r3_challenge: GroupOrderElement,
    s_challenge: GroupOrderElement,
    attribute_challenges: HashMap<usize, GroupOrderElement>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ProofProtocol {
    label: String,
    context: [u8; CONTEXT_BYTES],
    state: ProofTranscript
}

impl ProofProtocol {
    pub fn new(label: &str, disclosed_attributes: &[usize]) -> ProofProtocol {
        ProofProtocol::from_rng(label, disclosed_attributes,&mut thread_rng())
    }

    pub fn from_rng<R: Rng>(label: &str, disclosed_attributes: &[usize], rng: &mut R) -> ProofProtocol {
        let mut context = [0u8;  CONTEXT_BYTES];
        rng.fill_bytes(&mut context);
        ProofProtocol { label: label.to_string(), context, state: ProofTranscript::Request(ProofRequest { disclosed_attributes: HashSet::from_iter(disclosed_attributes.iter().cloned()) }) }
    }

    pub fn commit(&mut self, public_key: &PublicKey, signature: &Signature, attributes: &[GroupOrderElement]) -> Result<(), String> {
        let request;
        match &self.state {
            ProofTranscript::Request(ref req) => request = req,
            _ => return Err("commit can only be called when the transcript is a request".to_string())
        };

        let r1 = GroupOrderElement::new();
        let r2 = GroupOrderElement::new();
        let mut e_challenge = GroupOrderElement::new();
        let mut r2_challenge = GroupOrderElement::new();
        let mut r3_challenge = GroupOrderElement::new();
        let mut s_challenge = GroupOrderElement::new();

        let b = compute_b(&PointG1::new_infinity(), public_key, attributes, &signature.s, 0);

        let a_prime = &signature.a * &r1;
        let a_bar = (&b * &r1) - (&a_prime * &signature.e);
        let d = PointG1::mul2(&b, &r1, &public_key.h0, &r2);

        let mut r3 = r1.clone();
        r3.mod_inverse();
        let mut s_prime = signature.s.clone();
        s_prime += &(&r2 * &r3);

        let t1 = PointG1::mul2(&a_prime, &e_challenge, &public_key.h0, &r2_challenge);

        // d^r3~ * h0^-s'~
        let mut t2 = &public_key.h0 * &s_challenge - &d * &r3_challenge;

        let mut attribute_challenges = HashMap::new();

        for i in 0..attributes.len() {
            if !request.disclosed_attributes.contains(&i) {
                let r = GroupOrderElement::new();
                t2 += &public_key.h[i] * &r;
                attribute_challenges.insert(i, r);
            }
        }

        let mut challenge_bytes = Vec::new();
        challenge_bytes.extend_from_slice(self.label.as_bytes());
        challenge_bytes.extend_from_slice(&self.context);
        challenge_bytes.extend_from_slice(t1.to_bytes().as_slice());
        challenge_bytes.extend_from_slice(t2.to_bytes().as_slice());
        let hash_challenge = GroupOrderElement::from_hash::<sha2::Sha384>(challenge_bytes.as_slice());

        e_challenge += &(&hash_challenge * &signature.e);
        r2_challenge += &(&hash_challenge * &r2);
        r3_challenge += &(&hash_challenge * &r3);
        s_challenge += &(&hash_challenge * &s_prime);

        for (i, r) in attribute_challenges.iter_mut() {
            *r += &(&hash_challenge * &attributes[*i]);
        }

        let r = ProofR { a_prime, a_bar, d };
        let p = ProofP { e_challenge, r2_challenge, r3_challenge, s_challenge, attribute_challenges };
        let proof = Proof { hash_challenge, r, p };

        self.state = ProofTranscript::Fulfilled(proof);

        Ok(())
    }

    pub fn verify(&mut self, public_key: &PublicKey, disclosed_attributes: &HashMap<usize, GroupOrderElement>) -> Result<bool, String> {
        let proof;
        match &self.state {
            ProofTranscript::Fulfilled(ref req) => proof = req,
            _ => return Err("verify can only be called when the transcript is fulfilled".to_string())
        };

        if proof.r.a_prime.is_infinity() {
            return Ok(false);
        }

        if !Pair::pair_cmp(&proof.r.a_prime, &public_key.w, &proof.r.a_bar, &PointG2::base()) {
            return Ok(false);
        }

        let r_value = disclosed_attributes.iter().fold(PointG1::base(), |b, (i, a)| b + &public_key.h[*i] * a);

        let t1 = PointG1::mul2(&proof.r.a_prime, &proof.p.e_challenge, &(&proof.r.a_bar - &proof.r.d), &proof.hash_challenge) + (&public_key.h0 * &proof.p.r2_challenge);
        let acc = PointG1::mul2(&r_value, &proof.hash_challenge, &public_key.h0, &proof.p.s_challenge) - &proof.r.d * &proof.p.r3_challenge;

        let t2 = proof.p.attribute_challenges.iter().fold(acc, |b, (i, a)|b + &public_key.h[*i] * a);

        let mut challenge_bytes = Vec::new();
        challenge_bytes.extend_from_slice(self.label.as_bytes());
        challenge_bytes.extend_from_slice(&self.context);
        challenge_bytes.extend_from_slice(t1.to_bytes().as_slice());
        challenge_bytes.extend_from_slice(t2.to_bytes().as_slice());
        let hash_challenge = GroupOrderElement::from_hash::<sha2::Sha384>(challenge_bytes.as_slice());

        Ok(hash_challenge == proof.hash_challenge)
    }
}

fn compute_b(starting_value: &PointG1, public_key: &PublicKey, attributes: &[GroupOrderElement], blinding_factor: &GroupOrderElement, offset: usize) -> PointG1 {
    let mut b = PointG1::base();
    b += starting_value;

    let mut j = 0;
    let mut i = offset;


    while i + 1 < public_key.h.len() {
        let v1 = &attributes[j];
        let v2 = &attributes[j + 1];

        let p1 = &public_key.h[i];
        let p2 = &public_key.h[i + 1];


        b += PointG1::mul2(&p1, &v1, &p2, &v2);

        i += 2;
        j += 2;
    }

    if i < public_key.h.len() {
        let v = &attributes[j];
        let p = &public_key.h[i];

        b += PointG1::mul2(&p, &v, &public_key.h0, &blinding_factor);
    } else {
        b += &public_key.h0 * blinding_factor;
    }
    b
}

fn verify_signature(b: &PointG1, signature: &Signature, public_key: &PublicKey)  -> bool {
    let g2 = PointG2::base();
    let a = (&g2 * &signature.e) + public_key.w.clone();
    Pair::pair_cmp(&signature.a, &a, &b, &g2)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::FromBytes;

    #[test]
    fn key_generate() {
        let secret_key = SecretKey::new();
        assert_ne!(secret_key, SecretKey::from(0));
        let bytes = secret_key.to_bytes();
        assert_eq!(bytes.len(), SecretKey::BYTES_REPR_SIZE);
        let secret_key_2 = SecretKey::from_bytes(bytes);
        assert_eq!(secret_key_2, secret_key);

        let public_key = PublicKey::generate(5, &secret_key);
        assert_eq!(public_key.attributes(), 5);
        assert!(public_key.well_formed());
        let bytes = public_key.to_bytes();
        assert_eq!(bytes.len(), PointG2::BYTES_REPR_SIZE + PointG1::BYTES_REPR_SIZE * (public_key.attributes() + 1) + 4);
        let public_key_2 = PublicKey::from(bytes.as_slice());
        assert_eq!(public_key_2, public_key);

        let key_pair = KeyPair {
            public_key, secret_key
        };
        let correctness_proof = KeyCorrectnessProof::generate(&key_pair);
        assert!(correctness_proof.verify(&key_pair.public_key));
    }

    #[test]
    fn signature() {
        let key_pair = KeyPair::generate(5);

        let mut attributes = gen_attributes();
        let signature  = key_pair.sign(attributes.as_slice()).unwrap();
        assert!(key_pair.verify(&signature, attributes.as_slice()));
        attributes.remove(0);
        assert!(!key_pair.verify(&signature, attributes.as_slice()));
        let res = key_pair.sign(attributes.as_slice());
        assert!(res.is_err());
    }

    #[test]
    fn signing_transcript() {
        let key_pair = KeyPair::generate(5);
        let mut attributes = gen_attributes();
        let mut transcript = SignatureProtocol::new("cred1");

        assert!(transcript.issue_signature(&key_pair, attributes.as_slice()).is_err());
        assert!(transcript.complete_signature(&key_pair.public_key, &GroupOrderElement::new(), attributes.as_slice()).is_err());

        let res = transcript.blind_attributes(&key_pair.public_key, &attributes.as_slice()[0..2]);
        assert!(res.is_ok());
        let s = res.unwrap();

        assert!(transcript.blind_attributes(&key_pair.public_key, &attributes[0..2]).is_err());
        assert!(transcript.complete_signature(&key_pair.public_key, &s, attributes.as_slice()).is_err());

        let res = transcript.issue_signature(&key_pair, &attributes[2..]);

        assert!(res.is_ok());
        assert!(transcript.blind_attributes(&key_pair.public_key, &attributes[0..2]).is_err());
        assert!(transcript.issue_signature(&key_pair, &attributes[2..]).is_err());

        let res = transcript.complete_signature(&key_pair.public_key, &s, &attributes[2..]);

        assert!(res.is_ok());
        let signature = res.unwrap();

        assert!(transcript.blind_attributes(&key_pair.public_key, &attributes[0..2]).is_err());
        assert!(transcript.issue_signature(&key_pair,attributes.as_slice()).is_err());
        assert!(transcript.complete_signature(&key_pair.public_key, &s, &attributes[2..]).is_err());

        assert!(key_pair.verify(&signature, &attributes));

        transcript = SignatureProtocol::new("cred2");
        let s = transcript.blind_attributes(&key_pair.public_key, &attributes[0..1]).unwrap();
        assert!(transcript.issue_signature(&key_pair, &attributes[1..]).is_ok());
        assert!(transcript.complete_signature(&key_pair.public_key, &s, &attributes[1..]).is_ok());

        attributes.remove(1);

        transcript = SignatureProtocol::new("cred2");
        let res = transcript.blind_attributes(&key_pair.public_key, &attributes.as_slice()[0..2]);
        let _s= res.unwrap();

        let res = transcript.issue_signature(&key_pair, &attributes[2..]);
        assert!(res.is_err());

        //Try empty attributes
        let key_pair = KeyPair::generate(0);
        attributes.clear();
        transcript = SignatureProtocol::new("cred_with_zero_attributes");
        let res = transcript.blind_attributes(&key_pair.public_key, &[]);
        assert!(res.is_ok());
        let s = res.unwrap();
        let res = transcript.issue_signature(&key_pair, &[]);
        assert!(res.is_ok());
        let res = transcript.complete_signature(&key_pair.public_key, &s, &[]);
        assert!(res.is_ok());
    }

    #[test]
    fn proof_transcript() {
        let key_pair = KeyPair::generate(5);
        let attributes = gen_attributes();
        let mut transcript = SignatureProtocol::new("cred1");
        let s = transcript.blind_attributes(&key_pair.public_key, &attributes.as_slice()[0..1]).unwrap();
        transcript.issue_signature(&key_pair, &attributes[1..]).unwrap();
        let sig = transcript.complete_signature(&key_pair.public_key, &s, &attributes[1..]).unwrap();

        let disclosed_attributes_indices = vec![2, 4];
        let disclosed_attributes = disclosed_attributes_indices.iter().map(|i| (*i, attributes[*i].clone())).collect::<HashMap<usize, GroupOrderElement>>();

        let mut transcript = ProofProtocol::new("proof1", disclosed_attributes_indices.as_slice());

        assert!(transcript.verify(&key_pair.public_key, &disclosed_attributes).is_err());
        let res = transcript.commit(&key_pair.public_key, &sig, attributes.as_slice());
        assert!(res.is_ok());

        assert!(transcript.commit(&key_pair.public_key, &sig, attributes.as_slice()).is_err());

        let res = transcript.verify(&key_pair.public_key, &disclosed_attributes);
        assert!(res.is_ok());
        assert!(res.unwrap());
    }

    fn gen_attributes() -> Vec<GroupOrderElement> {
        vec![GroupOrderElement::new(), GroupOrderElement::new(), GroupOrderElement::new(), GroupOrderElement::new(), GroupOrderElement::new()]
    }
}
