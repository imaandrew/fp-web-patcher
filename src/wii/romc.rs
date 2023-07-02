const N: usize = 4096;
const F: usize = 18;
const THRESHOLD: usize = 2;
const FOUR_MBIT: usize = 4194304;

pub struct Romc {
    buf: [u8; N + F - 1],
    mtch: (usize, isize),
    left: [usize; N + 1],
    right: [usize; N + 257],
    parent: [usize; N + 1],
}

impl Default for Romc {
    fn default() -> Self {
        Self::new()
    }
}

impl Romc {
    pub const fn new() -> Self {
        Self {
            buf: [0; N + F - 1],
            mtch: (0, 0),
            left: [0; N + 1],
            right: [0; N + 257],
            parent: [0; N + 1],
        }
    }

    fn init(&mut self) {
        for i in N..=(N + 255) {
            self.right[i + 1] = N;
        }

        for i in 0..N {
            self.parent[i] = N;
        }
    }

    fn insert_node(&mut self, r: usize) {
        let mut cmp = 1;
        let key: &[u8] = &self.buf[r..];
        let mut p = N + 1 + key[0] as usize;
        self.right[r] = N;
        self.left[r] = N;
        self.mtch.1 = 0;

        loop {
            if cmp >= 0 {
                if self.right[p] == N {
                    self.right[p] = r;
                    self.parent[r] = p;
                    return;
                }
                p = self.right[p];
            } else if self.left[p] != N {
                p = self.left[p];
            } else {
                self.left[p] = r;
                self.parent[r] = p;
                return;
            }

            let mut ind = 1;
            for i in 1..F {
                cmp = key[ind] as isize - self.buf[p + i] as isize;
                if cmp != 0 {
                    break;
                }
                ind += 1;
            }

            if ind > self.mtch.1 as usize {
                self.mtch.0 = p;
                self.mtch.1 = ind as isize;
                if ind >= F {
                    break;
                }
            }
        }

        self.parent[r] = self.parent[p];
        self.left[r] = self.left[p];
        self.right[r] = self.right[p];
        self.parent[self.left[p]] = r;
        self.parent[self.right[p]] = r;
        if self.right[self.parent[p]] == p {
            self.right[self.parent[p]] = r;
        } else {
            self.left[self.parent[p]] = r;
        }
        self.parent[p] = N;
    }

    fn delete_node(&mut self, p: usize) {
        if self.parent[p] == N {
            return;
        }

        let q = if self.right[p] == N {
            self.left[p]
        } else if self.left[p] == N {
            self.right[p]
        } else {
            let mut q = self.left[p];
            if self.right[q] != N {
                loop {
                    q = self.right[q];
                    if self.right[q] == N {
                        break;
                    }
                }

                self.right[self.parent[q]] = self.left[q];
                self.parent[self.left[q]] = self.parent[q];
                self.left[q] = self.left[p];
                self.parent[self.left[p]] = q;
            }
            self.right[q] = self.right[p];
            self.parent[self.right[p]] = q;
            q
        };
        self.parent[q] = self.parent[p];
        if self.right[self.parent[p]] == p {
            self.right[self.parent[p]] = q;
        } else {
            self.left[self.parent[p]] = q;
        }
        self.parent[p] = N;
    }

    pub fn encode(&mut self, input: &[u8]) -> Vec<u8> {
        if input.is_empty() {
            return vec![];
        }

        let size = input.len() / FOUR_MBIT;
        let mut code_buf = [0; 17];
        let mut index = 1;
        let mut mask = 0x80;
        let mut s = 0;
        let mut r = N - F;
        let mut i = input.iter();

        let mut out = vec![size as u8, 0, 0, 1];

        self.init();

        for i in s..r {
            self.buf[i] = 0xff;
        }

        let mut len: isize = 0;

        for (ind, x) in i.by_ref().take(F).enumerate() {
            self.buf[r + ind] = *x;
            len += 1;
        }

        for i in 1..=F {
            self.insert_node(r - i);
        }

        self.insert_node(r);

        loop {
            if self.mtch.1 > len {
                self.mtch.1 = len;
            }

            if self.mtch.1 <= THRESHOLD as isize {
                self.mtch.1 = 1;
                code_buf[index] = self.buf[r];
                index += 1;
            } else {
                code_buf[0] |= mask;
                let uhhh = (((r as isize - self.mtch.0 as isize - 1) >> 8) & 0x0f) as u8
                    | ((self.mtch.1 - (THRESHOLD as isize + 1)) << 4) as u8;
                code_buf[index] = uhhh;
                let uhhh2 = ((r as isize - self.mtch.0 as isize - 1) & 0xff) as u8;
                code_buf[index + 1] = uhhh2;
                index += 2;
            }

            mask >>= 1;

            if mask == 0 {
                out.extend_from_slice(&code_buf[..index]);
                code_buf[0] = 0;
                index = 1;
                mask = 0x80;
            }

            let mut ind = 0;
            let last_match_len = self.mtch.1;
            for _ in 0..last_match_len {
                if let Some(x) = i.next() {
                    ind += 1;
                    self.delete_node(s);
                    self.buf[s] = *x;

                    if s < F - 1 {
                        self.buf[s + N] = *x;
                    }

                    s = (s + 1) & (N - 1);
                    r = (r + 1) & (N - 1);
                    self.insert_node(r);
                } else {
                    break;
                }
            }

            while ind < last_match_len {
                self.delete_node(s);
                s = (s + 1) & (N - 1);
                r = (r + 1) & (N - 1);
                len -= 1;
                if len != 0 {
                    self.insert_node(r);
                }
                ind += 1;
            }

            if len <= 0 {
                break;
            }
        }

        if index > 1 {
            out.extend_from_slice(&code_buf[..index]);
        }

        out.resize((out.len() + 3) & !3, 0);

        out
    }

    pub fn decode(&mut self, input: &[u8]) -> Vec<u8> {
        let mut i = input.iter();
        let decomp_size = match i.next() {
            Some(x) => *x as usize * FOUR_MBIT,
            None => return vec![],
        };
        let mut cur_size = 0;
        let mut i = i.skip(3);
        let mut out = vec![];
        let mut r = N - F;

        for i in 0..r {
            self.buf[i] = 0xff;
        }

        let mut flags = 7;
        let mut z = 7;

        loop {
            flags <<= 1;
            z += 1;
            if z == 8 {
                if let Some(x) = i.next() {
                    flags = *x;
                    z = 0;
                } else {
                    break;
                }
            }

            if flags & 0x80 == 0 {
                let c = match i.next() {
                    Some(x) => *x,
                    None => break,
                };

                if cur_size < decomp_size {
                    out.push(c);
                    self.buf[r] = c;
                    r += 1;
                    r &= N - 1;
                    cur_size += 1;
                }
            } else {
                let mut j = match i.next() {
                    Some(x) => *x as usize,
                    None => break,
                };
                let mut k = match i.next() {
                    Some(x) => *x as usize,
                    None => break,
                };

                k |= (j << 8) & 0xf00;
                j = ((j >> 4) & 0x0f) + THRESHOLD;
                for _ in 0..=j {
                    let c = self.buf[((r as isize - k as isize - 1) & (N - 1) as isize) as usize];
                    if cur_size < decomp_size {
                        out.push(c);
                        self.buf[r] = c;
                        r += 1;
                        r &= N - 1;
                        cur_size += 1;
                    }
                }
            }
        }

        out
    }
}
