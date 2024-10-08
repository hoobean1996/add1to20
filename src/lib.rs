use libc::{mmap, mprotect, MAP_ANONYMOUS, MAP_PRIVATE, PROT_EXEC, PROT_READ, PROT_WRITE};
use std::fs::File;
use std::io::{Result, Write};
use std::mem;

use std::collections::{HashMap, VecDeque};

#[derive(Clone, Copy, Debug)]
enum Op {
    Push(i64),
    Sub,
    Add,
    Store,
    Load,
    Bnez(i64),
    Halt,
}

use Op::*;

struct VirtualMachine {
    text: VecDeque<Op>,
    stack: VecDeque<i64>,
    rax: i64,
}

impl VirtualMachine {
    pub fn new(text: VecDeque<Op>) -> VirtualMachine {
        VirtualMachine {
            text,
            stack: VecDeque::new(),
            rax: 0,
        }
    }

    fn pop_value(&mut self) -> Option<i64> {
        self.stack.pop_back()
    }

    fn debug(&mut self, pc: usize) {
        println!("pc = {}, stack={:?}, rax={}", pc, self.stack, self.rax);
    }

    pub fn run(&mut self) -> Option<i64> {
        let mut pc = 0;
        loop {
            let op = self.text[pc];
            match &op {
                Sub => {
                    let right = self.pop_value().unwrap();
                    let left = self.pop_value().unwrap();
                    self.stack.push_back(left - right);
                }
                Add => {
                    let left = self.pop_value().unwrap();
                    let right = self.pop_value().unwrap();
                    self.stack.push_back(left + right);
                }
                Push(v) => {
                    self.stack.push_back(*v);
                }
                Store => {
                    self.rax = self.pop_value().unwrap();
                }
                Load => {
                    self.stack.push_back(self.rax);
                }
                Bnez(offset) => {
                    let v: i64 = self.pop_value().unwrap();
                    if v != 0 {
                        let pc1 = pc as i64 + offset;
                        pc = pc1 as usize - 1;
                        println!(
                            "benz={:?}, stack={:?}, rax={}",
                            self.text[pc], self.stack, self.rax
                        );
                    }
                }
                Halt => {
                    return self.pop_value();
                }
            }
            self.debug(pc);
            pc += 1;
        }
    }

    pub fn run_with_aot_literal(&mut self, a: i32, b: i32) -> Option<i64> {
        let func: extern "C" fn(i32, i32) -> i32 = unsafe { mem::transmute(self.aot_literal()) };
        Some(func(a, b) as i64)
    }

    pub fn run_with_aot(&mut self) -> Option<i64> {
        let func: extern "C" fn() -> i32 = unsafe { mem::transmute(self.aot()) };
        Some(func() as i64)
    }

    fn aot(&mut self) -> *const i32 {
        let mut buffer: Vec<u8> = vec![];
        let mut labels: HashMap<i32, usize> = HashMap::new();
        // Prologue
        buffer.extend_from_slice(&[
            0x55, // push rbp
            0x48, 0x89, 0xe5, // mov rbp, rsp
        ]);

        let mut pc: usize = 0;
        loop {
            labels.insert(pc as i32, buffer.len());
            let op = self.text[pc];
            match op {
                Op::Push(value) => {
                    // mov rax, imm64
                    buffer.push(0x48);
                    buffer.push(0xb8);
                    buffer.extend_from_slice(&value.to_le_bytes());
                    // push rax
                    buffer.push(0x50);
                }
                Op::Add => {
                    // pop rdi
                    buffer.push(0x5f);
                    // pop rax
                    buffer.push(0x58);
                    // add rax, rdi
                    buffer.extend_from_slice(&[0x48, 0x01, 0xf8]);
                    // push rax
                    buffer.push(0x50);
                }
                Op::Store => {
                    // pop rax
                    buffer.push(0x58);
                    // mov [rbp-8], rax
                    buffer.extend_from_slice(&[0x48, 0x89, 0x45, 0xf8]);
                }
                Op::Load => {
                    // mov rax, [rbp-8]
                    buffer.extend_from_slice(&[0x48, 0x8b, 0x45, 0xf8]);
                    // push rax
                    buffer.push(0x50);
                }
                Op::Halt => {
                    // mov rax, [rbp-8]
                    buffer.extend_from_slice(&[0x48, 0x8b, 0x45, 0xf8]);
                    break;
                }
                _ => panic!("Not supported yet"),
            }
            pc += 1;
        }

        // Epilogue
        buffer.extend_from_slice(&[
            0x5d, // pop rbp
            0xc3, // ret
        ]);

        self.write_buffer_hex_to_file(&buffer, "adder");

        let size = buffer.len();

        let ptr = unsafe {
            mmap(
                std::ptr::null_mut(),
                size,
                PROT_READ | PROT_WRITE,
                MAP_PRIVATE | MAP_ANONYMOUS,
                -1,
                0,
            )
        };

        if ptr == libc::MAP_FAILED {
            panic!("mmap failed");
        }

        // Copy the machine code to the executable memory
        unsafe {
            std::ptr::copy_nonoverlapping(buffer.as_ptr(), ptr as *mut u8, size);
        }

        // Make the memory executable
        unsafe {
            mprotect(ptr, size, PROT_READ | PROT_EXEC);
        }

        ptr as *const i32
    }

    fn write_buffer_hex_to_file(&mut self, buffer: &[u8], filename: &str) -> Result<()> {
        let mut file = File::create(filename)?;
        let mut output = String::new();

        for (i, &byte) in buffer.iter().enumerate() {
            if i % 16 == 0 {
                if i > 0 {
                    output.push('\n');
                }
                output.push_str(&format!("{:04x}: ", i));
            }
            output.push_str(&format!("{:02x} ", byte));
        }
        output.push('\n');

        file.write_all(output.as_bytes())?;
        Ok(())
    }

    fn aot_literal(&mut self) -> *const i32 {
        let mut buffer: Vec<u8> = vec![];
        // Prologue
        buffer.extend_from_slice(&[
            0x55, // push rbp
            0x48, 0x89, 0xe5, // mov rbp, rsp
        ]);

        // Add operation
        buffer.extend_from_slice(&[
            0x89, 0x7d, 0xfc, 0x89, 0x75, 0xf8, 0x8b, 0x55, 0xfc, 0x8b, 0x45, 0xf8, 0x01, 0xd0,
        ]);

        // Epilogue
        buffer.extend_from_slice(&[
            0x5d, // pop rbp
            0xc3, // ret
        ]);

        let size = buffer.len();

        let ptr = unsafe {
            mmap(
                std::ptr::null_mut(),
                size,
                PROT_READ | PROT_WRITE,
                MAP_PRIVATE | MAP_ANONYMOUS,
                -1,
                0,
            )
        };

        if ptr == libc::MAP_FAILED {
            panic!("mmap failed");
        }

        // Copy the machine code to the executable memory
        unsafe {
            std::ptr::copy_nonoverlapping(buffer.as_ptr(), ptr as *mut u8, size);
        }

        // Make the memory executable
        unsafe {
            mprotect(ptr, size, PROT_READ | PROT_EXEC);
        }

        ptr as *const i32
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;

    use crate::{Op::*, VirtualMachine};

    #[test]
    pub fn test_vm() {
        {
            let mut vm = VirtualMachine::new(VecDeque::from(vec![Halt]));
            assert_eq!(vm.run(), None);
        }

        {
            let mut vm = VirtualMachine::new(VecDeque::from(vec![Push(1), Halt]));
            assert_eq!(vm.run(), Some(1));
        }

        {
            let mut vm = VirtualMachine::new(VecDeque::from(vec![Push(1), Push(2), Add, Halt]));
            assert_eq!(vm.run(), Some(3));
        }

        {
            let mut vm = VirtualMachine::new(VecDeque::from(vec![Push(5), Push(3), Sub, Halt]));
            assert_eq!(vm.run(), Some(2));
        }

        {
            let mut vm = VirtualMachine::new(VecDeque::from(vec![
                Push(20),
                Store,
                Push(0),
                Load,
                Add,
                Load,
                Push(1),
                Sub,
                Store,
                Load,
                Bnez(-7),
                Halt,
            ]));
            assert_eq!(vm.run(), Some(210));
        }

        {
            let mut vm = VirtualMachine::new(VecDeque::from(vec![
                Push(20),
                Store,
                Push(0),
                Load,
                Add,
                Load,
                Push(1),
                Sub,
                Store,
                Load,
                Bnez(-7),
                Halt,
            ]));
            assert_eq!(vm.run(), Some(210));
        }
    }

    #[test]
    pub fn test_aot() {
        let mut vm = VirtualMachine::new(VecDeque::from(vec![]));
        assert_eq!(vm.run_with_aot_literal(100, 20), Some(120));
    }

    #[test]
    pub fn test_bytecode_aot() {
        let mut vm =
            VirtualMachine::new(VecDeque::from(vec![Push(123), Push(12), Add, Store, Halt]));
        assert_eq!(vm.run_with_aot(), Some(135));
    }
}
