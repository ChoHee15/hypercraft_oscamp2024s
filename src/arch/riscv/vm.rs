use core::{arch::asm, panic};

use super::{
    devices::plic::{PlicState, MAX_CONTEXTS},
    regs::GeneralPurposeRegisters,
    sbi::{BaseFunction, IPIFunction, PmuFunction, RemoteFenceFunction},
    traps,
    vcpu::{self, VmCpuRegisters},
    vm_pages::VmPages,
    HyperCallMsg, RiscvCsrTrait, CSR,
};
use crate::{
    arch::sbi::{HSMFunction, SBI_ERR_NOT_SUPPORTED}, vcpus::VM_CPUS_MAX, GprIndex, GuestPageTableTrait, GuestPhysAddr, GuestVirtAddr, HyperCraftHal, HyperError, HyperResult, VCpu, VmCpuStatus, VmCpus, VmExitInfo
};
use alloc::{collections::VecDeque, vec::Vec};
use riscv::addr::BitField;
use riscv_decode::Instruction;
use sbi_rt::{pmu_counter_get_info, pmu_counter_stop, SbiRet};
use spin::{mutex::Mutex};

// ADDED multi-bounding
const VCPU_NUM: usize = 2;

/// A VM that is being run.
pub struct VM<H: HyperCraftHal, G: GuestPageTableTrait> {
    vcpus: VmCpus<H>,
    gpt: G,
    vm_pages: VmPages,
    plic: PlicState,

    // ADDED multi-bounding
    // TODO: num???
    // regs: [Option<GeneralPurposeRegisters>; VCPU_NUM], 
    // switched: [bool; VCPU_NUM],
    // timer_pending: Mutex<VecDeque<isize>>,
    // next_timer: Option<u64>,
    // timer_vec: Mutex<VecDeque<u64>>,
    // timer_vec: VecDeque<u64>,
    timer_vec: Vec<VecDeque<u64>>,
    ipi_flag: [bool; VCPU_NUM],

}

impl<H: HyperCraftHal, G: GuestPageTableTrait> VM<H, G> {
    /// Create a new VM with `vcpus` vCPUs and `gpt` as the guest page table.
    pub fn new(vcpus: VmCpus<H>, gpt: G) -> HyperResult<Self> {
        Ok(Self {
            vcpus,
            gpt,
            vm_pages: VmPages::default(),
            plic: PlicState::new(0xC00_0000),

            // ADDED multi-bounding
            // regs: [None; VCPU_NUM],
            // switched: [false; VCPU_NUM],
            // timer_pending: Mutex::new(VecDeque::new()),
            // next_timer: None,
            // timer_vec: Mutex::new(VecDeque::new()),
            // timer_vec: VecDeque::new(),
            timer_vec: vec![VecDeque::new(); VCPU_NUM],
            ipi_flag: [false; VCPU_NUM],
        })
    }

    /// Initialize `VCpu` by `vcpu_id`.
    pub fn init_vcpu(&mut self, vcpu_id: usize) {
        let vcpu = self.vcpus.get_vcpu(vcpu_id).unwrap();
        vcpu.init_page_map(self.gpt.token());
    }

    /// Add cpu to vcpus
    pub fn add_vcpu(&mut self, vcpu: VCpu<H>) -> HyperResult{
        self.vcpus.add_vcpu(vcpu)
    }

    /// Waiting sync
    // pub fn sync_vcpu(&mut self, vcpu_id: usize) {
    //     let vcpu = self.vcpus.get_vcpu(vcpu_id).unwrap();
    //     loop {
    //         let state = vcpu.get_status();
    //         match state {
    //             VmCpuStatus::Runnable =>{
    //                 debug!("VCPU{} ready to run!!!", vcpu_id);
    //                 break;
    //             }
    //             VmCpuStatus::Running => {
    //                 panic!("wtf??");
    //             }
    //             _ => {
    //                 core::hint::spin_loop();
    //             }
    //         }
    //     }
    // }
    pub fn sync_vcpu(&mut self, vcpu_id: usize) -> bool{
        let vcpu = self.vcpus.get_vcpu(vcpu_id).unwrap();
        loop {
            let state = vcpu.get_status();
            match state {
                VmCpuStatus::Runnable =>{
                    if vcpu_id != 0 {
                        debug!("VCPU{} ready to run!!!", vcpu_id);
                    }
                    break;
                }
                VmCpuStatus::Running => {
                    panic!("wtf??");
                }
                _ => {
                    core::hint::spin_loop();
                    // MODIFIED
                    debug!("VCPU{} sync failed, yield", vcpu_id);
                    return false;
                }
            }
        }
        true
    }

    #[allow(unused_variables, deprecated)]
    /// Run the host VM's vCPU with ID `vcpu_id`. Does not return.
    pub fn run(&mut self, vcpu_id: usize) {
        // ADDED
        // self.sync_vcpu(vcpu_id);
        if !self.sync_vcpu(vcpu_id) {
            return;
        }

        let mut vm_exit_info: VmExitInfo;

        // MODIFIED
        let mut gprs = GeneralPurposeRegisters::default();
        // let mut gprs = if let Some(res) = self.regs[vcpu_id] {
        //     res
        // }else{
        //     GeneralPurposeRegisters::default()
        // };
        
        // ADDED
        // info!("eeeee");
        // let mtime = unsafe { core::ptr::read_volatile(0x200_BFF8 as *const u32) };
        // info!("bbbbbb");
        // sbi_rt::set_timer((mtime + 50000) as u64);


        // self.timer_pending.lock().clear();
        // assert!(self.timer_pending.lock().is_empty());
        fn read_time() -> u64 {
            let mut time: u64;
            unsafe {
                asm!(
                    "rdtime {time}",
                    time = out(reg) time
                );
            }
            time
        }
        // let now_time = read_time();
        let target_time = read_time() + 50000;
        // error!("now is {}", now_time);
        // sbi_rt::set_timer(read_time() + 50000); //100000
        sbi_rt::set_timer(target_time);
        debug!("VCPU{} will exit after {}",vcpu_id, target_time);
        // // self.timer_pending.lock().push_back(0);
        CSR.sie
            .read_and_set_bits(traps::interrupt::SUPERVISOR_TIMER);

        // info!("VCPU{} host timer set!", vcpu_id);

        if self.ipi_flag[vcpu_id] {
            debug!("VCPU{} need ipi!", vcpu_id);
            let sbi_ret = sbi_rt::send_ipi(0x1, 0x0);
            self.ipi_flag[vcpu_id] = false;
        }

        

        loop {
            let mut len = 4;
            let mut advance_pc = false;

            // let now = read_time();
            // if let Some(next) = self.next_timer {
            //     if now >= next {
            //         // error!("VCPU{} next timer expired!", vcpu_id);
            //         CSR.hvip
            //             .read_and_set_bits(traps::interrupt::VIRTUAL_SUPERVISOR_TIMER);
            //         self.next_timer = None;
            //     }
            // }

            // assert!(self.timer_vec.lock().is_empty());
            // assert!(self.timer_vec.is_empty());

            {
                let vcpu = self.vcpus.get_vcpu(vcpu_id).unwrap();
                // ADDED
                vcpu.set_status(VmCpuStatus::Running);
                vm_exit_info = vcpu.run();
                // ADDED
                vcpu.set_status(VmCpuStatus::Runnable);
                vcpu.save_gprs(&mut gprs);
            }

            // ADDED
            let mut switch_flag = false;

            fn read_tp() -> usize {
                let tp: usize;
                unsafe {
                    // 使用内联汇编读取tp寄存器
                    // 这里的`0`是临时寄存器，`tp`是目标寄存器
                    asm!(
                        "mv {}, tp", // 将tp寄存器的值移动到临时寄存器
                        lateout(reg) tp, // 将临时寄存器的值输出到tp变量
                        options(nostack, nomem, preserves_flags)
                    );
                }
                tp
            }
            debug!("VCPU{} htp: {:#x}, vtp: {:#x}", vcpu_id, read_tp(), gprs.reg(GprIndex::TP));

            error!("VCPU{} exit info: {:#?}", vcpu_id, vm_exit_info);
            

            match vm_exit_info {
                VmExitInfo::Ecall(sbi_msg) => {
                    if let Some(sbi_msg) = sbi_msg {
                        match sbi_msg {
                            HyperCallMsg::Base(base) => {
                                self.handle_base_function(base, &mut gprs).unwrap();
                            }
                            HyperCallMsg::GetChar => {
                                error!("VCPU{} get char!!", vcpu_id);
                                let c = sbi_rt::legacy::console_getchar();
                                // ang?
                                gprs.set_reg(GprIndex::A0, c);
                            }
                            HyperCallMsg::PutChar(c) => {
                                error!("VCPU{} put char!!", vcpu_id);
                                sbi_rt::legacy::console_putchar(c);
                            }
                            HyperCallMsg::SetTimer(timer) => {
                                sbi_rt::set_timer(timer as u64);
                                error!("VCPU{} guest set {}", vcpu_id, timer);
                                // assert!(*self.timer_vec.lock().back().unwrap() < timer as u64);
                                // self.timer_vec.lock().push_back(timer as u64);
                                if !self.timer_vec[vcpu_id].is_empty() {
                                    assert!(*self.timer_vec[vcpu_id].back().unwrap() < timer as u64);
                                }
                                self.timer_vec[vcpu_id].push_back(timer as u64);
                                // Clear guest timer interrupt
                                CSR.hvip.read_and_clear_bits(
                                    traps::interrupt::VIRTUAL_SUPERVISOR_TIMER,
                                );
                                //  Enable host timer interrupt
                                CSR.sie
                                    .read_and_set_bits(traps::interrupt::SUPERVISOR_TIMER);

                                // ADDED
                                // let mut guard = self.timer_pending.lock();
                                // guard.push_back(1);

                                // CSR.hvip.read_and_clear_bits(
                                //     traps::interrupt::VIRTUAL_SUPERVISOR_TIMER,
                                // );
                                // // assert_matches!(self.next_timer, None);
                                // assert!(self.next_timer == None);
                                // self.next_timer = Some(timer as u64);
                                
                                // debug!("VCPU{} set timer & switch", vcpu_id);
                                // switch_flag = true;
                                
                            }
                            HyperCallMsg::Reset(_) => {
                                sbi_rt::system_reset(sbi_rt::Shutdown, sbi_rt::SystemFailure);
                            }
                            HyperCallMsg::RemoteFence(rfnc) => {
                                self.handle_rfnc_function(rfnc, &mut gprs).unwrap();
                            }
                            HyperCallMsg::PMU(pmu) => {
                                self.handle_pmu_function(pmu, &mut gprs).unwrap();
                            }
                            // ADDED
                            HyperCallMsg::HSM(hsm) => {
                                debug!("vcpu{} HSM calling !", vcpu_id);
                                self.handle_hsm_function(hsm, &mut gprs).unwrap();
                            }
                            HyperCallMsg::SPI(spi) => {
                                debug!("vcpu{} SPI calling !", vcpu_id);
                                self.handle_spi_function(spi, &mut gprs).unwrap();
                                switch_flag = true;
                            }
                            _ => todo!(),
                        }
                        advance_pc = true;
                    } else {
                        panic!()
                    }
                }
                VmExitInfo::PageFault {
                    fault_addr,
                    falut_pc,
                    inst,
                    priv_level,
                } => {
                    // info!("VCPU{} page fault ({:#x}, {:#x}, {:#x}, {:#?})", vcpu_id, fault_addr, falut_pc, inst, priv_level);
                    match priv_level {
                    super::vmexit::PrivilegeLevel::Supervisor => {
                        match self.handle_page_fault(falut_pc, inst, fault_addr, &mut gprs) {
                            Ok(inst_len) => {
                                len = inst_len;
                            }
                            Err(err) => {
                                panic!(
                                    "Page fault at {:#x} addr@{:#x} with error {:?}",
                                    falut_pc, fault_addr, err
                                )
                            }
                        }
                        advance_pc = true;
                    }
                    super::vmexit::PrivilegeLevel::User => {
                        panic!("User page fault")
                    }
                }},
                VmExitInfo::TimerInterruptEmulation => {
                    // debug!("timer irq emulation");
                    // Enable guest timer interrupt
                    // MODIFIED
                    // CSR.hvip
                    //     .read_and_set_bits(traps::interrupt::VIRTUAL_SUPERVISOR_TIMER);

                    // Clear host timer interrupt
                    CSR.sie
                        .read_and_clear_bits(traps::interrupt::SUPERVISOR_TIMER);

                    let now = read_time();
                    
                    if !self.timer_vec[vcpu_id].is_empty() {
                        assert!(now >= *self.timer_vec[vcpu_id].front().unwrap());
                    }

                    let tmp = self.timer_vec[vcpu_id].pop_front();

                    if !self.timer_vec[vcpu_id].is_empty() {
                        assert!(now < *self.timer_vec[vcpu_id].front().unwrap());
                    }

                    if now <= target_time {
                        debug!("VCPU{} guest timer {} expired when now is {}!", vcpu_id, tmp.unwrap(), now);
                        CSR.hvip
                            .read_and_set_bits(traps::interrupt::VIRTUAL_SUPERVISOR_TIMER);
                        sbi_rt::set_timer(target_time);
                        // // self.timer_pending.lock().push_back(0);
                        CSR.sie
                            .read_and_set_bits(traps::interrupt::SUPERVISOR_TIMER);
                    }else{
                        debug!("VCPU{} host timer expired when now is {}!", vcpu_id, now);
                        switch_flag = true;
                    }



                    // if read_time() >= target_time {
                    //     // error!("VCPU{} next timer expired!", vcpu_id);
                    //     switch_flag = true;
                    // }else {
                    //     CSR.hvip
                    //     .read_and_set_bits(traps::interrupt::VIRTUAL_SUPERVISOR_TIMER);
                    // }

                    
                    // // ADDED switch
                    // let mut guard = self.timer_pending.lock();
                    // assert!(guard.len() <= 2, "deque size:{} with {:#?}", guard.len(), guard);
                    // let res = guard.pop_front().unwrap();

                    // assert!((res == 0) || (res == 1));

                    // if res == 1 {
                    //     debug!("VCPU{} get guest timer int, countinue", vcpu_id);
                    //     CSR.hvip
                    //         .read_and_set_bits(traps::interrupt::VIRTUAL_SUPERVISOR_TIMER);
                    //     if guard.is_empty() {
                    //         // Clear host timer interrupt
                    //         CSR.sie
                    //             .read_and_clear_bits(traps::interrupt::SUPERVISOR_TIMER);
                    //     }
                    // }else{
                    //     debug!("VCPU{} get host timer int, go to switch", vcpu_id);
                    //     switch_flag = true;
                    //     // Clear host timer interrupt
                    //     CSR.sie
                    //         .read_and_clear_bits(traps::interrupt::SUPERVISOR_TIMER);
                    // }
                    
                    // debug!("VCPU{} set switch flag", vcpu_id);


                    // let now = read_time();
                    // let next = self.next_timer.unwrap();
                    // if now >= next {
                    //     error!("VCPU{} next timer expired!", vcpu_id);
                    //     CSR.hvip
                    //         .read_and_set_bits(traps::interrupt::VIRTUAL_SUPERVISOR_TIMER);
                    //     self.next_timer = None;
                    // }
                    // switch_flag = true;

                }
                VmExitInfo::ExternalInterruptEmulation => self.handle_irq(vcpu_id),
                // ADDED
                VmExitInfo::SoftInterruptEmulation => {
                    // TODO
                    // 这块内容河里吗
                    error!("VCPU{} software emulation", vcpu_id);
                    let mut sip = riscv::register::sip::read().bits();
                    // debug!("SIP: {:#x}", sip);
                    let res = sip.set_bit(1, false);
                    // debug!("Modified SIP {:#x}", res);
                    riscv::register::sip::write(*res);
                    // riscv::register::satp::write(res);
                    // core::arch::asm!("csrrs {0}, {1}, x0", out(reg) r, const $csr_number);
                    // sbi_rt::legacy::clear_ipi();
                    CSR.hvip
                        .read_and_set_bits(traps::interrupt::VIRTUAL_SUPERVISOR_SOFT);
                }
                _ => {}
            }

            {
                let vcpu = self.vcpus.get_vcpu(vcpu_id).unwrap();
                vcpu.restore_gprs(&gprs);
                if advance_pc {
                    vcpu.advance_pc(len);
                }

                // assert!(self.ipi_flag[vcpu_id] == false);
                // assert!(self.timer_vec[vcpu_id].is_empty());

                // MODIFIED
                if switch_flag {
                    // self.regs[vcpu_id] = Some(gprs);
                    // error!("VCPU{} switch!!!", vcpu_id);
                    // self.switched[vcpu_id] = true;
                    // Clear host timer interrupt
                    CSR.sie
                        .read_and_clear_bits(traps::interrupt::SUPERVISOR_TIMER);
                    return;
                }
            }
        }
    }
}

// Privaie methods implementation
impl<H: HyperCraftHal, G: GuestPageTableTrait> VM<H, G> {
    fn handle_page_fault(
        &mut self,
        inst_addr: GuestVirtAddr,
        inst: u32,
        fault_addr: GuestPhysAddr,
        gprs: &mut GeneralPurposeRegisters,
    ) -> HyperResult<usize> {
        //  plic
        if fault_addr >= self.plic.base() && fault_addr < self.plic.base() + 0x0400_0000 {
            self.handle_plic(inst_addr, inst, fault_addr, gprs)
        } else {
            error!("inst_addr: {:#x}, fault_addr: {:#x}", inst_addr, fault_addr);
            Err(HyperError::PageFault)
        }
    }

    #[allow(clippy::needless_late_init)]
    fn handle_plic(
        &mut self,
        inst_addr: GuestVirtAddr,
        mut inst: u32,
        fault_addr: GuestPhysAddr,
        gprs: &mut GeneralPurposeRegisters,
    ) -> HyperResult<usize> {
        if inst == 0 {
            // If hinst does not provide information about trap,
            // we must read the instruction from guest's memory maunally.
            inst = self.vm_pages.fetch_guest_instruction(inst_addr)?;
        }
        let i1 = inst as u16;
        let len = riscv_decode::instruction_length(i1);
        let inst = match len {
            2 => i1 as u32,
            4 => inst,
            _ => unreachable!(),
        };
        // assert!(len == 4);
        let decode_inst = riscv_decode::decode(inst).map_err(|_| HyperError::DecodeError)?;
        match decode_inst {
            Instruction::Sw(i) => {
                let val = gprs.reg(GprIndex::from_raw(i.rs2()).unwrap()) as u32;
                self.plic.write_u32(fault_addr, val)
            }
            Instruction::Lw(i) => {
                let val = self.plic.read_u32(fault_addr);
                gprs.set_reg(GprIndex::from_raw(i.rd()).unwrap(), val as usize)
            }
            _ => return Err(HyperError::InvalidInstruction),
        }
        Ok(len)
    }

    fn handle_irq(&mut self, vcpu_id: usize) {
        error!("VPU{} handle irq", vcpu_id);
        let context_id = vcpu_id * 2 + 1;
        let claim_and_complete_addr = self.plic.base() + 0x0020_0004 + 0x1000 * context_id;
        let irq = unsafe { core::ptr::read_volatile(claim_and_complete_addr as *const u32) };
        // TODO ang?
        // assert!(irq != 0);

        // let reg_mmode_addr = self.plic.base() + 0x0020_0004 + 0x1000 * (vcpu_id * 2);
        // let m_irq = unsafe { core::ptr::read_volatile(reg_mmode_addr as *const u32) };
        // debug!("handle_irq {}:{} in vcpu{}@{:#x}", m_irq, irq, vcpu_id, claim_and_complete_addr);

        // let irq2 = unsafe { core::ptr::read_volatile(claim_and_complete_addr as *const u32) };
        // debug!("double run : {}", irq2);
        
        // let hart0_m_addr = self.plic.base() + 0x0020_0004 + 0x1000 * (0 * 2);
        // let hart0_m_irq = unsafe { core::ptr::read_volatile(hart0_m_addr as *const u32) };
        // let hart0_s_addr = self.plic.base() + 0x0020_0004 + 0x1000 * (0 * 2 + 1);
        // let hart0_s_irq = unsafe { core::ptr::read_volatile(hart0_s_addr as *const u32) };

        // let hart1_m_addr = self.plic.base() + 0x0020_0004 + 0x1000 * (1 * 2);
        // let hart1_m_irq = unsafe { core::ptr::read_volatile(hart1_m_addr as *const u32) };
        // let hart1_s_addr = self.plic.base() + 0x0020_0004 + 0x1000 * (1 * 2 + 1);
        // let hart1_s_irq = unsafe { core::ptr::read_volatile(hart1_s_addr as *const u32) };

        // debug!("HART0 {}:{}", hart0_m_irq, hart0_s_irq);
        // debug!("HART1 {}:{}", hart1_m_irq, hart1_s_irq);

        if irq == 0{
            error!("handle_irq vcpu{} error?", vcpu_id);
            // assert!(vcpu_id != 0);
            // assert!(vcpu_id != 1);
            // panic!("wah???");
        }
        
        self.plic.claim_complete[context_id] = irq;

        CSR.hvip
            .read_and_set_bits(traps::interrupt::VIRTUAL_SUPERVISOR_EXTERNAL);
    }

    fn handle_base_function(
        &self,
        base: BaseFunction,
        gprs: &mut GeneralPurposeRegisters,
    ) -> HyperResult<()> {
        match base {
            BaseFunction::GetSepcificationVersion => {
                let version = sbi_rt::get_spec_version();
                gprs.set_reg(GprIndex::A1, version.major() << 24 | version.minor());
                debug!(
                    "GetSepcificationVersion: {}",
                    version.major() << 24 | version.minor()
                );
            }
            BaseFunction::GetImplementationID => {
                let id = sbi_rt::get_sbi_impl_id();
                gprs.set_reg(GprIndex::A1, id);
            }
            BaseFunction::GetImplementationVersion => {
                let impl_version = sbi_rt::get_sbi_impl_version();
                gprs.set_reg(GprIndex::A1, impl_version);
            }
            BaseFunction::ProbeSbiExtension(extension) => {
                let extension = sbi_rt::probe_extension(extension as usize).raw;
                gprs.set_reg(GprIndex::A1, extension);
            }
            BaseFunction::GetMachineVendorID => {
                let mvendorid = sbi_rt::get_mvendorid();
                gprs.set_reg(GprIndex::A1, mvendorid);
            }
            BaseFunction::GetMachineArchitectureID => {
                let marchid = sbi_rt::get_marchid();
                gprs.set_reg(GprIndex::A1, marchid);
            }
            BaseFunction::GetMachineImplementationID => {
                let mimpid = sbi_rt::get_mimpid();
                gprs.set_reg(GprIndex::A1, mimpid);
            }
        }
        gprs.set_reg(GprIndex::A0, 0);
        Ok(())
    }

    fn handle_pmu_function(
        &self,
        pmu: PmuFunction,
        gprs: &mut GeneralPurposeRegisters,
    ) -> HyperResult<()> {
        gprs.set_reg(GprIndex::A0, 0);
        match pmu {
            PmuFunction::GetNumCounters => gprs.set_reg(GprIndex::A1, sbi_rt::pmu_num_counters()),
            PmuFunction::GetCounterInfo(counter_index) => {
                let sbi_ret = pmu_counter_get_info(counter_index as usize);
                gprs.set_reg(GprIndex::A0, sbi_ret.error);
                gprs.set_reg(GprIndex::A1, sbi_ret.value);
            }
            PmuFunction::StopCounter {
                counter_index,
                counter_mask,
                stop_flags,
            } => {
                let sbi_ret = pmu_counter_stop(
                    counter_index as usize,
                    counter_mask as usize,
                    stop_flags as usize,
                );
                gprs.set_reg(GprIndex::A0, sbi_ret.error);
                gprs.set_reg(GprIndex::A1, sbi_ret.value);
            }
        }
        Ok(())
    }

    fn handle_rfnc_function(
        &self,
        rfnc: RemoteFenceFunction,
        gprs: &mut GeneralPurposeRegisters,
    ) -> HyperResult<()> {
        gprs.set_reg(GprIndex::A0, 0);
        match rfnc {
            RemoteFenceFunction::FenceI {
                hart_mask,
                hart_mask_base,
            } => {
                assert!(hart_mask_base == 0);
                let sbi_ret = sbi_rt::remote_fence_i(hart_mask as usize, hart_mask_base as usize);
                gprs.set_reg(GprIndex::A0, sbi_ret.error);
                gprs.set_reg(GprIndex::A1, sbi_ret.value);
            }
            RemoteFenceFunction::RemoteSFenceVMA {
                hart_mask,
                hart_mask_base,
                start_addr,
                size,
            } => {
                assert!(hart_mask_base == 0);
                let sbi_ret = sbi_rt::remote_sfence_vma(
                    hart_mask as usize,
                    hart_mask_base as usize,
                    start_addr as usize,
                    size as usize,
                );
                gprs.set_reg(GprIndex::A0, sbi_ret.error);
                gprs.set_reg(GprIndex::A1, sbi_ret.value);
            }
            // ADDED
            RemoteFenceFunction::RemoteSFenceVMA_ASID { 
                hart_mask, 
                hart_mask_base, 
                start_addr, 
                size, 
                asid 
            } => {
                assert!(hart_mask_base == 0);
                let sbi_ret = sbi_rt::remote_sfence_vma_asid(
                    hart_mask as usize,
                    hart_mask_base as usize,
                    start_addr as usize,
                    size as usize,
                    asid as usize,
                );
                gprs.set_reg(GprIndex::A0, sbi_ret.error);
                gprs.set_reg(GprIndex::A1, sbi_ret.value);
            }
        }
        Ok(())
    }

    // ADDED
    fn handle_hsm_function(
        &mut self,
        hsm: HSMFunction,
        gprs: &mut GeneralPurposeRegisters,
    ) -> HyperResult<()> {
        debug!("---handling hsm function!");
        match hsm {
            HSMFunction::HART_START{
                hartid,
                start_addr,
                opaque,
            } => {
                debug!("---guest hsm start:({}, {:#x}, {:#x})", hartid, start_addr, opaque);


                
                let vcpu = self.vcpus.get_vcpu(hartid).unwrap();

                vcpu.set_gpr(GprIndex::A0, hartid);
                vcpu.set_gpr(GprIndex::A1, opaque);
                vcpu.set_spec(start_addr);

                // vcpu.set_gpr(GprIndex::TP, 0xffffffd8016aad00);

                vcpu.set_status(VmCpuStatus::Runnable);
                debug!("---guest hsm start set runnable {}", hartid);


                let sbi_ret = SbiRet::success(0);
                gprs.set_reg(GprIndex::A0, sbi_ret.error);
                gprs.set_reg(GprIndex::A1, sbi_ret.value);
                // debug!("---guest hsm start return {}", hartid);
            }
            HSMFunction::HART_STOP => {
                panic!("TODO");
            }
            HSMFunction::HART_GET_STATUS { 
                hartid: _ 
            } =>{
                panic!("TODO");
            }
            HSMFunction::HART_SUSPEND { 
                suspend_type: _, 
                resume_addr: _, 
                opaque: _ 
            } => {
                panic!("unknown HSMFunction");
            }
        }
        Ok(())
    }

    // ADDED
    fn handle_spi_function(
        &mut self,
        spi: IPIFunction,
        gprs: &mut GeneralPurposeRegisters,
    ) -> HyperResult<()> {
        // debug!("---handling spi function!");
        match spi {
            IPIFunction::SEND_IPI{
                hart_mask,
                hart_mask_base, 
            } => {
                debug!("---guest send ipi:({:#x}, {:#x})", hart_mask, hart_mask_base);

                // let sbi_ret = sbi_rt::send_ipi(hart_mask, hart_mask_base);

                // gprs.set_reg(GprIndex::A0, sbi_ret.error);
                // gprs.set_reg(GprIndex::A1, sbi_ret.value);

                // assert!(self.ipi_flag[hart_mask_base] == false);
                self.ipi_flag[hart_mask_base] = true;

                let sbi_ret = SbiRet::success(0);
                gprs.set_reg(GprIndex::A0, sbi_ret.error);
                gprs.set_reg(GprIndex::A1, sbi_ret.value);
            }
        }
        Ok(())
    }
}
