//! A small deterministic binary codec. Every consensus object serialises one way only.

use crate::hash::{bytes_to_words, words_to_bytes, Word8};

#[derive(Default, Clone)]
pub struct Writer(pub Vec<u8>);

impl Writer {
    pub fn new() -> Self {
        Self(Vec::new())
    }
    pub fn u8(&mut self, v: u8) -> &mut Self {
        self.0.push(v);
        self
    }
    pub fn u32(&mut self, v: u32) -> &mut Self {
        self.0.extend_from_slice(&v.to_le_bytes());
        self
    }
    pub fn u64(&mut self, v: u64) -> &mut Self {
        self.0.extend_from_slice(&v.to_le_bytes());
        self
    }
    pub fn bool(&mut self, v: bool) -> &mut Self {
        self.u8(v as u8)
    }
    pub fn raw(&mut self, b: &[u8]) -> &mut Self {
        self.0.extend_from_slice(b);
        self
    }
    pub fn bytes(&mut self, b: &[u8]) -> &mut Self {
        self.u32(b.len() as u32);
        self.raw(b)
    }
    pub fn word8(&mut self, w: &Word8) -> &mut Self {
        self.raw(&words_to_bytes(w))
    }
    pub fn rho(&mut self, r: &[u32; 5]) -> &mut Self {
        for x in r {
            self.raw(&x.to_be_bytes());
        }
        self
    }
    pub fn u64s(&mut self, v: &[u64]) -> &mut Self {
        self.u32(v.len() as u32);
        for x in v {
            self.u64(*x);
        }
        self
    }
    pub fn words(&mut self, v: &[Word8]) -> &mut Self {
        self.u32(v.len() as u32);
        for x in v {
            self.word8(x);
        }
        self
    }
    pub fn into_inner(self) -> Vec<u8> {
        self.0
    }
}

pub struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

pub type Res<T> = Result<T, String>;

impl<'a> Reader<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }
    pub fn done(&self) -> bool {
        self.pos == self.buf.len()
    }
    pub fn finish(&self) -> Res<()> {
        if self.done() {
            Ok(())
        } else {
            Err(format!("{} trailing bytes", self.buf.len() - self.pos))
        }
    }
    pub fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }
    pub fn raw(&mut self, n: usize) -> Res<&'a [u8]> {
        if n > self.remaining() {
            return Err("unexpected end of data".into());
        }
        let s = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }
    pub fn arr<const N: usize>(&mut self) -> Res<[u8; N]> {
        Ok(self.raw(N)?.try_into().unwrap())
    }
    pub fn u8(&mut self) -> Res<u8> {
        Ok(self.raw(1)?[0])
    }
    pub fn bool(&mut self) -> Res<bool> {
        match self.u8()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err("bad bool".into()),
        }
    }
    pub fn u32(&mut self) -> Res<u32> {
        Ok(u32::from_le_bytes(self.arr()?))
    }
    pub fn u64(&mut self) -> Res<u64> {
        Ok(u64::from_le_bytes(self.arr()?))
    }
    pub fn bytes(&mut self, max: usize) -> Res<Vec<u8>> {
        let n = self.u32()? as usize;
        if n > max {
            return Err(format!("field of {n} bytes exceeds {max}"));
        }
        Ok(self.raw(n)?.to_vec())
    }
    pub fn word8(&mut self) -> Res<Word8> {
        Ok(bytes_to_words(&self.arr()?))
    }
    pub fn rho(&mut self) -> Res<[u32; 5]> {
        let mut r = [0u32; 5];
        for x in r.iter_mut() {
            *x = u32::from_be_bytes(self.arr()?);
        }
        Ok(r)
    }
    pub fn u64s(&mut self, max: usize) -> Res<Vec<u64>> {
        let n = self.u32()? as usize;
        if n > max {
            return Err("vector too long".into());
        }
        (0..n).map(|_| self.u64()).collect()
    }
    pub fn words(&mut self, max: usize) -> Res<Vec<Word8>> {
        let n = self.u32()? as usize;
        if n > max {
            return Err("vector too long".into());
        }
        (0..n).map(|_| self.word8()).collect()
    }
}
