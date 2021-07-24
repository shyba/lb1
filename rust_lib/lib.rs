use pyo3::exceptions::PyValueError;
use pyo3::prelude::{pyfunction, pymodule, wrap_pyfunction, PyModule, PyResult, Python};
use std::convert::TryInto;
use std::mem::transmute;

#[pyfunction]
fn py_sha256_transform(payload: &[u8]) -> PyResult<[u8; 32]> {
    if payload.len() != 64 {
        return Err(PyValueError::new_err(
            "payload needs to be exactly 64 bytes long",
        ));
    }
    Ok(sha256_transform(payload.try_into().unwrap()))
}

const H: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];
const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

// https://en.wikipedia.org/wiki/SHA-2
fn sha256_transform(payload: &[u8; 64]) -> [u8; 32] {
    let mut w: [u32; 64] = [0; 64];

    for (idx, chunk) in payload.chunks(4).enumerate() {
        w[idx] = u32::from_be_bytes(chunk.try_into().unwrap());
    }
    for idx in 16..64 {
        let s0 = w[idx - 15];
        let s0 = (s0 >> 7 | s0 << 25) ^ (s0 >> 18 | s0 << 14) ^ (s0 >> 3);
        let s1 = w[idx - 2];
        let s1 = (s1 >> 17 | s1 << 15) ^ (s1 >> 19 | s1 << 13) ^ (s1 >> 10);
        w[idx] = w[idx - 16]
            .wrapping_add(s0)
            .wrapping_add(w[idx - 7])
            .wrapping_add(s1)
    }
    //println!("w = {:?}", w);

    let mut a: u32 = H[0];
    let mut b: u32 = H[1];
    let mut c: u32 = H[2];
    let mut d: u32 = H[3];
    let mut e: u32 = H[4];
    let mut f: u32 = H[5];
    let mut g: u32 = H[6];
    let mut h: u32 = H[7];

    fn round(
        a: u32,
        b: u32,
        c: u32,
        _d: u32,
        e: u32,
        f: u32,
        g: u32,
        h: u32,
        k: u32,
        w: u32,
    ) -> (u32, u32) {
        let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
        let ch = (e & f) ^ (!(e) & g);
        let temp1 = h
            .wrapping_add(s1)
            .wrapping_add(ch)
            .wrapping_add(k)
            .wrapping_add(w);
        let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
        let maj = (a & b) ^ (a & c) ^ (b & c);
        let temp2 = s0.wrapping_add(maj);
        (temp1, temp2)
    }
    for idx in 0..64 {
        //println!("{} = {} {} {} {} {} {} {} {}", idx, a, b, c, d, e, f, g, h);
        let (temp1, temp2) = round(a, b, c, d, e, f, g, h, K[idx], w[idx]);
        h = g;
        g = f;
        f = e;
        e = d.wrapping_add(temp1);
        d = c;
        c = b;
        b = a;
        a = temp1.wrapping_add(temp2);
    }
    a = u32::from_be(H[0].wrapping_add(a));
    b = u32::from_be(H[1].wrapping_add(b));
    c = u32::from_be(H[2].wrapping_add(c));
    d = u32::from_be(H[3].wrapping_add(d));
    e = u32::from_be(H[4].wrapping_add(e));
    f = u32::from_be(H[5].wrapping_add(f));
    g = u32::from_be(H[6].wrapping_add(g));
    h = u32::from_be(H[7].wrapping_add(h));
    unsafe { transmute([a, b, c, d, e, f, g, h]) }
}

#[pymodule]
fn lb1ext(_py: Python<'_>, m: &PyModule) -> PyResult<()> {
    m.add_wrapped(wrap_pyfunction!(py_sha256_transform))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vectors() {
        let result = sha256_transform(&[0; 64]);
        assert_eq!(
            result,
            [
                0xda, 0x56, 0x98, 0xbe, 0x17, 0xb9, 0xb4, 0x69, 0x62, 0x33, 0x57, 0x99, 0x77, 0x9f,
                0xbe, 0xca, 0x8c, 0xe5, 0xd4, 0x91, 0xc0, 0xd2, 0x62, 0x43, 0xba, 0xfe, 0xf9, 0xea,
                0x18, 0x37, 0xa9, 0xd8
            ]
        );

        let result = sha256_transform(&[
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
            24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45,
            46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63,
        ]);
        assert_eq!(
            result,
            [
                252, 153, 162, 223, 136, 244, 42, 122, 123, 185, 209, 128, 51, 205, 198, 162, 2,
                86, 117, 95, 157, 91, 154, 80, 68, 169, 204, 49, 90, 190, 132, 167
            ]
        );

        let result = sha256_transform(&[255; 64]);
        assert_eq!(
            result,
            [
                239, 12, 116, 141, 244, 218, 80, 168, 214, 196, 60, 1, 62, 220, 60, 231, 108, 157,
                159, 169, 161, 69, 138, 222, 86, 235, 134, 192, 166, 68, 146, 210
            ]
        );
    }
}
