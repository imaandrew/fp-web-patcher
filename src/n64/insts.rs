#[derive(Clone, Copy, Debug)]
pub struct Instruction {
    pub ty: Type,
    pub size: u32,
    pub mode: u32,
}

#[derive(Clone, Copy, Debug)]
pub enum Type {
    Add,
    Run,
    Copy,
}

#[derive(Debug)]
pub struct CodeTable {
    pub table: [(Instruction, Option<Instruction>); 256],
}

impl Default for CodeTable {
    fn default() -> Self {
        let mut table = [(
            Instruction {
                ty: Type::Run,
                size: 0,
                mode: 0,
            },
            None,
        ); 256];

        let mut index = 1;
        for size in 0..18 {
            table[index] = (
                Instruction {
                    ty: Type::Add,
                    size,
                    mode: 0,
                },
                None,
            );
            index += 1;
        }

        for mode in 0..9 {
            table[index] = (
                Instruction {
                    ty: Type::Copy,
                    size: 0,
                    mode,
                },
                None,
            );
            index += 1;
            for size in 4..19 {
                table[index] = (
                    Instruction {
                        ty: Type::Copy,
                        size,
                        mode,
                    },
                    None,
                );
                index += 1;
            }
        }

        for mode in 0..9 {
            for add_size in 1..5 {
                let range = if mode < 6 { 4..7 } else { 4..5 };
                for copy_size in range {
                    table[index] = (
                        Instruction {
                            ty: Type::Add,
                            size: add_size,
                            mode: 0,
                        },
                        Some(Instruction {
                            ty: Type::Copy,
                            size: copy_size,
                            mode,
                        }),
                    );
                    index += 1;
                }
            }
        }

        for mode in 0..9 {
            table[index] = (
                Instruction {
                    ty: Type::Copy,
                    size: 4,
                    mode,
                },
                Some(Instruction {
                    ty: Type::Add,
                    size: 1,
                    mode: 0,
                }),
            );
            index += 1;
        }

        Self { table }
    }
}
