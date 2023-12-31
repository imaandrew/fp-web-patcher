use super::{read_byte, read_int, VCDiffDecoderError};

pub struct AddrCache {
    near: Vec<u32>,
    next_slot: usize,
    same: Vec<u32>,
}

impl Default for AddrCache {
    fn default() -> Self {
        Self::new(4, 3)
    }
}

impl AddrCache {
    pub fn new(s_near: usize, s_same: usize) -> Self {
        Self {
            near: vec![0; s_near],
            next_slot: 0,
            same: vec![0; s_same * 256],
        }
    }

    pub fn cache_update(&mut self, addr: u32) {
        self.near[self.next_slot] = addr;
        self.next_slot = (self.next_slot + 1) % self.near.capacity();
        let cap = self.same.capacity();
        self.same[addr as usize % cap] = addr;
    }

    pub fn addr_decode(
        &mut self,
        here: u32,
        mode: u32,
        index: &mut usize,
        addr: &[u8],
    ) -> Result<u32, VCDiffDecoderError> {
        let addr = if mode == 0 {
            read_int(addr, index)?
        } else if mode == 1 {
            here - read_int(addr, index)?
        } else if mode >= 2 && mode as usize - 2 < self.near.capacity() {
            self.near[(mode - 2) as usize] + read_int(addr, index)?
        } else {
            let m = mode as usize - 2 - self.near.capacity();
            self.same
                .get(m * 256 + read_byte(addr, index)? as usize)
                .ok_or(VCDiffDecoderError::IndexOutOfBounds(
                    1,
                    *index - 1,
                    self.same.len(),
                ))
                .copied()?
        };

        self.cache_update(addr);
        Ok(addr)
    }
}
