#[macro_use]
extern crate criterion;

use criterion::Criterion;

extern crate anoncred_signatures;

use anoncred_signatures::{bbs, bls381};

fn bbs_keypair_benchmark(c: &mut Criterion) {
    for i in vec![0, 1, 2, 4, 5, 10, 20, 30, 40, 50, 60, 70, 80, 90, 100] {
        let atts = i;
        c.bench_function(format!("create key for {}", i).as_str(), move |b| b.iter(||bbs::KeyPair::generate(atts)));
    }
}

fn bbs_sign_benchmark(c: &mut Criterion) {
    for i in vec![0, 1, 2, 4, 5, 10, 20, 30, 40, 50, 60, 70, 80, 90, 100] {
        let atts = i;
        let keypair = bbs::KeyPair::generate(atts);
        let mut attributes = Vec::new();
        for j in 0..i {
            attributes.push(bls381::FieldOrderElement::new());
        }
        c.bench_function(format!("sign {} atts", i).as_str(), move |b|b.iter(|| keypair.sign(attributes.as_slice())));
    }
}

criterion_group!(
    name = bench_bbs;
    config = Criterion::default();
    targets = bbs_keypair_benchmark, bbs_sign_benchmark);
criterion_main!(bench_bbs);

