use core::{f32::consts::E, panic};

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
use riscv::addr::BitField;
use riscv_decode::Instruction;
use sbi_rt::{pmu_counter_get_info, pmu_counter_stop, SbiRet};
use tock_registers::interfaces::Writeable;

use crate::timer::OS_TIMER;
use riscv::register::time;

/// A VM that is being run.
pub struct VM<H: HyperCraftHal, G: GuestPageTableTrait> {
    vcpus: VmCpus<H>,
    gpt: G,
    vm_pages: VmPages,
    plic: PlicState,

    
    // ADDED
    guest_timer: Option<u64>,
    
}

impl<H: HyperCraftHal, G: GuestPageTableTrait> VM<H, G> {
    /// Create a new VM with `vcpus` vCPUs and `gpt` as the guest page table.
    pub fn new(vcpus: VmCpus<H>, gpt: G) -> HyperResult<Self> {
        Ok(Self {
            vcpus,
            gpt,
            vm_pages: VmPages::default(),
            plic: PlicState::new(0xC00_0000),
            //ADDED
            guest_timer: None,
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
    pub fn sync_vcpu(&mut self, vcpu_id: usize) {
        let vcpu = self.vcpus.get_vcpu(vcpu_id).unwrap();
        loop {
            let state = vcpu.get_status();
            match state {
                VmCpuStatus::Runnable =>{
                    debug!("VCPU{} ready to run!!!", vcpu_id);
                    break;
                }
                VmCpuStatus::Running => {
                    panic!("wtf??");
                }
                _ => {
                    core::hint::spin_loop();
                }
            }
        }
    }

    #[allow(unused_variables, deprecated)]
    /// Run the host VM's vCPU with ID `vcpu_id`. Does not return.
    pub fn run(&mut self, vcpu_id: usize) {
        // ADDED
        self.sync_vcpu(vcpu_id);

        let mut vm_exit_info: VmExitInfo;
        let mut gprs = GeneralPurposeRegisters::default();
        loop {

            let now = time::read64();
            let guard = OS_TIMER.lock();
            let mut os_timer = *guard;
            drop(guard);

            error!("ostimer {}  vs  now {}", os_timer, now);


            if now > os_timer {
                // panic!("no way");
                // error!("emmmm")
                error!("active trap to arceos to update os timer!!!");
                sbi_rt::set_timer(0);
                CSR.sie
                    .read_and_set_bits(traps::interrupt::SUPERVISOR_TIMER);
                CSR.sie
                    .read_and_clear_bits(traps::interrupt::SUPERVISOR_TIMER);
                os_timer = *OS_TIMER.lock();
            }

            sbi_rt::set_timer(os_timer);

            if let Some(guest_timer) = self.guest_timer {
                if now >= guest_timer{
                    CSR.hvip
                        .read_and_set_bits(traps::interrupt::VIRTUAL_SUPERVISOR_TIMER);
                }

                if guest_timer < os_timer {
                    sbi_rt::set_timer(guest_timer);
                    self.guest_timer = None;
                    debug!("clear & set guest timer {}!", guest_timer);
                }else {
                    debug!("set os timer {}!", os_timer);
                }
            }else {
                debug!("no guest timer, so set os timer {}", os_timer);
            }

            // CSR.sie
            //     .read_and_set_bits(traps::interrupt::SUPERVISOR_TIMER);



            let mut len = 4;
            let mut advance_pc = false;
            {
                let vcpu = self.vcpus.get_vcpu(vcpu_id).unwrap();
                // ADDED
                vcpu.set_status(VmCpuStatus::Running);
                vm_exit_info = vcpu.run();
                // ADDED
                vcpu.set_status(VmCpuStatus::Runnable);
                vcpu.save_gprs(&mut gprs);
            }

            info!("vm info: {:#?}", vm_exit_info);

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
                                assert!(matches!(self.guest_timer, None));
                                self.guest_timer = Some(timer as u64);
                                debug!("Guest set a timer {}", timer);

                                // sbi_rt::set_timer(timer as u64);
                                // // Clear guest timer interrupt
                                // CSR.hvip.read_and_clear_bits(
                                //     traps::interrupt::VIRTUAL_SUPERVISOR_TIMER,
                                // );
                                // //  Enable host timer interrupt
                                // CSR.sie
                                //     .read_and_set_bits(traps::interrupt::SUPERVISOR_TIMER);
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
                                trace!("vcpu{} SPI calling !", vcpu_id);
                                self.handle_spi_function(spi, &mut gprs).unwrap();
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
                } => match priv_level {
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
                },
                VmExitInfo::TimerInterruptEmulation => {
                    error!("int!");
                    // let os_g = OS_TIMER.lock();
                    // let os_t = *os_g;
                    // drop(os_g);
                    // let now = time::read64() * 1000;
                    // error!("ostimer {}  vs  now {}", os_t, now);
                    // if os_t <=  now{
                    //     error!("active trap to arceos to update os timer!!!");
                    //     sbi_rt::set_timer(0);
                    //     CSR.sie
                    //         .read_and_set_bits(traps::interrupt::SUPERVISOR_TIMER);
                    //     CSR.sie
                    //         .read_and_clear_bits(traps::interrupt::SUPERVISOR_TIMER);
                    // }

                    // // debug!("timer irq emulation");
                    // // Enable guest timer interrupt
                    // CSR.hvip
                    //     .read_and_set_bits(traps::interrupt::VIRTUAL_SUPERVISOR_TIMER);
                    // // Clear host timer interrupt
                    // CSR.sie
                    //     .read_and_clear_bits(traps::interrupt::SUPERVISOR_TIMER);
                }
                VmExitInfo::ExternalInterruptEmulation => self.handle_irq(vcpu_id),
                // ADDED
                VmExitInfo::SoftInterruptEmulation => {
                    // TODO
                    // 这块内容河里吗
                    // debug!("VCPU{} software emulation", vcpu_id);
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
        let context_id = vcpu_id * 2 + 1;
        let claim_and_complete_addr = self.plic.base() + 0x0020_0004 + 0x1000 * context_id;
        let irq = unsafe { core::ptr::read_volatile(claim_and_complete_addr as *const u32) };
        // TODO ang?
        // assert!(irq != 0);
        let reg_mmode_addr = self.plic.base() + 0x0020_0004 + 0x1000 * (vcpu_id * 2);
        let m_irq = unsafe { core::ptr::read_volatile(reg_mmode_addr as *const u32) };
        debug!("handle_irq {}:{} in vcpu{}@{:#x}", m_irq, irq, vcpu_id, claim_and_complete_addr);
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
            error!("handle_irq vcpu{} error", vcpu_id);
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
                trace!("---guest send ipi:({:#x}, {:#x})", hart_mask, hart_mask_base);

                let sbi_ret = sbi_rt::send_ipi(hart_mask, hart_mask_base);

                gprs.set_reg(GprIndex::A0, sbi_ret.error);
                gprs.set_reg(GprIndex::A1, sbi_ret.value);
            }
        }
        Ok(())
    }
}
