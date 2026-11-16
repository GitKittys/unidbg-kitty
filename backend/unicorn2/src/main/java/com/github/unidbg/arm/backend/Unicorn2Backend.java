package com.github.unidbg.arm.backend;

import com.github.unidbg.Emulator;
import com.github.unidbg.arm.backend.unicorn.Unicorn;
import com.github.unidbg.debugger.BreakPoint;
import com.github.unidbg.debugger.BreakPointCallback;
import com.github.unidbg.thread.ThreadContextSwitchException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import unicorn.UnicornConst;
import unicorn.UnicornException;

import java.security.SecureRandom;
import java.util.Map;

class Unicorn2Backend extends AbstractBackend implements Backend, SysRegBackend {

    private static final Logger log = LoggerFactory.getLogger(Unicorn2Backend.class);

    private final Emulator<?> emulator;
    private final boolean is64Bit;
    private final Unicorn unicorn;
    /** the native library has the system register API (built from the unidbg engine fork for this platform) */
    private final boolean sysRegApi;
    /** the native library counts executed instructions (built from the unidbg engine fork) */
    private final boolean insnCount;
    private final boolean memoryFaultSignals;

    Unicorn2Backend(Emulator<?> emulator, boolean is64Bit, boolean pointerAuthentication, boolean memoryFaultSignals) throws BackendException {
        this.emulator = emulator;
        this.is64Bit = is64Bit;
        this.memoryFaultSignals = memoryFaultSignals;
        try {
            if (is64Bit) {
                this.unicorn = new Unicorn(UnicornConst.UC_ARCH_ARM64, UnicornConst.UC_MODE_ARM);
                this.sysRegApi = hasSysRegApi(unicorn);
                if (pointerAuthentication && sysRegApi) {
                    enablePointerAuthentication();
                }
            } else {
                this.unicorn = new Unicorn(UnicornConst.UC_ARCH_ARM, UnicornConst.UC_MODE_ARM);
                this.sysRegApi = false;
            }
            this.insnCount = sysRegApi && hasInsnCount(unicorn);
        } catch (UnicornException e) {
            throw new BackendException(e);
        }
    }

    private void checkSysRegApi() {
        if (!sysRegApi) {
            throw new BackendException("the unicorn2 native library for this platform has no system register API");
        }
    }

    private static boolean hasSysRegApi(Unicorn unicorn) {
        try {
            unicorn.cp_reg_read(3, 0, 0, 0, 0); // MIDR_EL1
            return true;
        } catch (UnsatisfiedLinkError e) {
            log.warn("the unicorn2 native library for this platform predates the system register API (rebuild it with " +
                    "backend/unicorn2/src/main/native/build.sh): EL0 boundary, pointer authentication setup and CPU feature view are off");
            return false;
        }
    }

    private static boolean hasInsnCount(Unicorn unicorn) {
        try {
            unicorn.insn_count();
            return true;
        } catch (UnsatisfiedLinkError | UnicornException e) {
            log.warn("the unicorn2 native library for this platform does not count instructions (rebuild it with " +
                    "backend/unicorn2/src/main/native/build.sh): the guest's clocks stay on host time");
            return false;
        }
    }

    @Override
    public long insn_count() {
        return insnCount ? unicorn.insn_count() : -1;
    }

    /**
     * FEAT_PAuth as the kernel sets it up for a process: every key with a random value (so signed pointers differ from
     * run to run, as on a device), all of them enabled in SCTLR_EL1.
     */
    private void enablePointerAuthentication() {
        int[][] keys = {
                {1, 0}, {1, 1}, {1, 2}, {1, 3}, // APIAKey{Lo,Hi}_EL1, APIBKey{Lo,Hi}_EL1
                {2, 0}, {2, 1}, {2, 2}, {2, 3}, // APDAKey{Lo,Hi}_EL1, APDBKey{Lo,Hi}_EL1
                {3, 0}, {3, 1}, // APGAKey{Lo,Hi}_EL1
        };
        SecureRandom random = new SecureRandom();
        try {
            unicorn.cp_reg_write(3, 0, 2, keys[0][0], keys[0][1], random.nextLong());
        } catch (UnicornException e) {
            log.debug("the CPU model has no pointer authentication", e);
            return;
        }
        try {
            for (int i = 1; i < keys.length; i++) {
                unicorn.cp_reg_write(3, 0, 2, keys[i][0], keys[i][1], random.nextLong());
            }
            final long enIA = 1L << 31, enIB = 1L << 30, enDA = 1L << 27, enDB = 1L << 13;
            long sctlr = unicorn.cp_reg_read(3, 0, 1, 0, 0);
            unicorn.cp_reg_write(3, 0, 1, 0, 0, sctlr | enIA | enIB | enDA | enDB);
        } catch (UnicornException e) {
            log.warn("pointer authentication setup failed, it stays off", e);
        }
    }

    @Override
    public void switchUserMode() {
        switchUserMode(is64Bit);
    }

    @Override
    public void enableVFP() {
        enableVFP(is64Bit);
    }

    @Override
    public byte[] reg_read_vector(int regId) throws BackendException {
        checkVectorRegId(regId, is64Bit);
        try {
            return unicorn.reg_read(regId, 16);
        } catch (UnicornException e) {
            throw new BackendException(e);
        }
    }

    @Override
    public void reg_write_vector(int regId, byte[] vector) throws BackendException {
        if (vector.length != 16) {
            throw new IllegalStateException("Invalid vector size");
        }
        checkVectorRegId(regId, is64Bit);
        try {
            unicorn.reg_write(regId, vector);
        } catch (UnicornException e) {
            throw new BackendException(e);
        }
    }

    @Override
    public Number reg_read(int regId) throws BackendException {
        try {
            return unicorn.reg_read(regId);
        } catch (UnicornException e) {
            throw new BackendException(e);
        }
    }

    @Override
    public void reg_write(int regId, Number value) throws BackendException {
        try {
            unicorn.reg_write(regId, is64Bit ? value.longValue() : value.intValue());
        } catch (UnicornException e) {
            throw new BackendException(e);
        }
    }

    @Override
    public byte[] mem_read(long address, long size) throws BackendException {
        try {
            return unicorn.mem_read(address, size);
        } catch (UnicornException e) {
            throw new BackendException("mem_read address=0x" + Long.toHexString(address) + ", size=" + size, e);
        }
    }

    @Override
    public void mem_write(long address, byte[] bytes) throws BackendException {
        try {
            unicorn.mem_write(address, bytes);
        } catch (UnicornException e) {
            throw new BackendException("mem_write address=0x" + Long.toHexString(address), e);
        }
    }

    @Override
    public void mem_map(long address, long size, int perms) throws BackendException {
        try {
            unicorn.mem_map(address, size, perms);
        } catch (UnicornException e) {
            throw new BackendException("mem_map address=0x" + Long.toHexString(address) + ", size=" + size + ", perms=0x" + Integer.toHexString(perms), e);
        }
    }

    @Override
    public void mem_protect(long address, long size, int perms) throws BackendException {
        try {
            unicorn.mem_protect(address, size, perms);
        } catch (UnicornException e) {
            throw new BackendException("mem_protect address=0x" + Long.toHexString(address) + ", size=" + size + ", perms=0x" + Integer.toHexString(perms), e);
        }
    }

    @Override
    public void mem_unmap(long address, long size) throws BackendException {
        try {
            unicorn.mem_unmap(address, size);
        } catch (UnicornException e) {
            throw new BackendException("mem_unmap address=0x" + Long.toHexString(address) + ", size=" + size, e);
        }
    }

    @Override
    public BreakPoint addBreakPoint(long address, BreakPointCallback callback, boolean thumb) {
        BreakPointImpl breakPoint = new BreakPointImpl(callback, thumb);
        unicorn.addBreakPoint(address);
        return breakPoint;
    }

    @Override
    public boolean removeBreakPoint(long address) {
        unicorn.removeBreakPoint(address);
        return true;
    }

    @Override
    public void setSingleStep(int singleStep) {
        unicorn.setSingleStep(singleStep);
    }

    @Override
    public void setFastDebug(boolean fastDebug) {
        unicorn.setFastDebug(fastDebug);
    }

    @Override
    public void removeJitCodeCache(long begin, long end) throws BackendException {
        unicorn.removeJitCodeCache(begin, end);
    }

    @Override
    public void hook_add_new(final CodeHook callback, long begin, long end, Object user_data) throws BackendException {
        try {
            final Unicorn.UnHook unHook = unicorn.hook_add_new((com.github.unidbg.arm.backend.unicorn.CodeHook) (u, address, size, user) ->
                    callback.hook(Unicorn2Backend.this, address, size, user), begin, end, user_data);
            callback.onAttach(unHook::unhook);
        } catch (UnicornException e) {
            throw new BackendException(e);
        }
    }

    @Override
    public void debugger_add(final DebugHook callback, long begin, long end, Object user_data) throws BackendException {
        try {
            final Unicorn.UnHook unHook = unicorn.debugger_add(new com.github.unidbg.arm.backend.unicorn.DebugHook() {
                @Override
                public void onBreak(Unicorn u, long address, int size, Object user) {
                    callback.onBreak(Unicorn2Backend.this, address, size, user);
                }

                @Override
                public void hook(Unicorn u, long address, int size, Object user) {
                    callback.hook(Unicorn2Backend.this, address, size, user);
                }
            }, begin, end, user_data);
            callback.onAttach(unHook::unhook);
        } catch (UnicornException e) {
            throw new BackendException(e);
        }
    }

    @Override
    public void hook_add_new(final ReadHook callback, long begin, long end, Object user_data) throws BackendException {
        try {
            final Unicorn.UnHook unHook = unicorn.hook_add_new((com.github.unidbg.arm.backend.unicorn.ReadHook) (u, address, size, user) ->
                    callback.hook(Unicorn2Backend.this, address, size, user), begin, end, user_data);
            callback.onAttach(unHook::unhook);
        } catch (UnicornException e) {
            throw new BackendException(e);
        }
    }

    @Override
    public void hook_add_new(final WriteHook callback, long begin, long end, Object user_data) throws BackendException {
        try {
            final Unicorn.UnHook unHook = unicorn.hook_add_new((u, address, size, value, user) ->
                    callback.hook(Unicorn2Backend.this, address, size, value, user), begin, end, user_data);
            callback.onAttach(unHook::unhook);
        } catch (UnicornException e) {
            throw new BackendException(e);
        }
    }

    @Override
    public void hook_add_new(final EventMemHook callback, final int type, Object user_data) throws BackendException {
        if ((type & UnicornConst.UC_HOOK_MEM_READ_UNMAPPED) != 0) {
            hookEventMem(callback, UnicornConst.UC_HOOK_MEM_READ_UNMAPPED, user_data, EventMemHook.UnmappedType.Read);
        }
        if ((type & UnicornConst.UC_HOOK_MEM_WRITE_UNMAPPED) != 0) {
            hookEventMem(callback, UnicornConst.UC_HOOK_MEM_WRITE_UNMAPPED, user_data, EventMemHook.UnmappedType.Write);
        }
        if ((type & UnicornConst.UC_HOOK_MEM_FETCH_UNMAPPED) != 0) {
            hookEventMem(callback, UnicornConst.UC_HOOK_MEM_FETCH_UNMAPPED, user_data, EventMemHook.UnmappedType.Fetch);
        }
    }

    @Override
    public boolean isMemoryFaultSignals() {
        return memoryFaultSignals;
    }

    @Override
    public void hook_add_protection_fault(EventMemHook callback, Object user_data) throws BackendException {
        checkSysRegApi();
        hookEventMem(callback, UnicornConst.UC_HOOK_MEM_READ_PROT, user_data, EventMemHook.UnmappedType.Read);
        hookEventMem(callback, UnicornConst.UC_HOOK_MEM_WRITE_PROT, user_data, EventMemHook.UnmappedType.Write);
        hookEventMem(callback, UnicornConst.UC_HOOK_MEM_FETCH_PROT, user_data, EventMemHook.UnmappedType.Fetch);
    }

    private void hookEventMem(final EventMemHook callback, final int type, Object user_data, final EventMemHook.UnmappedType unmappedType) {
        try {
            Map<Integer, Unicorn.UnHook> map = unicorn.hook_add_new((u, address, size, value, user) ->
                    callback.hook(Unicorn2Backend.this, address, size, value, user, unmappedType), type, user_data);
            for (final Unicorn.UnHook unHook : map.values()) {
                callback.onAttach(unHook::unhook);
            }
        } catch (UnicornException e) {
            throw new BackendException(e);
        }
    }

    @Override
    public void hook_add_new(final InterruptHook callback, Object user_data) throws BackendException {
        try {
            final Unicorn.UnHook unHook = unicorn.hook_add_new((u, intno, user) -> {
                int swi = decodeSWI(emulator, Unicorn2Backend.this, is64Bit);
                callback.hook(Unicorn2Backend.this, intno, swi, user);
            }, user_data);
            callback.onAttach(unHook::unhook);
        } catch (UnicornException e) {
            throw new BackendException(e);
        }
    }

    @Override
    public void hook_add_new(final SysRegHook callback, final int insn, Object user_data) throws BackendException {
        checkSysRegApi();
        try {
            unicorn.hook_add_new((com.github.unidbg.arm.backend.unicorn.SysRegHook) (u, op0, op1, crn, crm, op2, val, user) ->
                    callback.hook(Unicorn2Backend.this, insn, op0, op1, crn, crm, op2, val, user), insn, user_data,
                    callback.passthrough(insn));
        } catch (UnicornException e) {
            throw new BackendException(e);
        }
    }

    @Override
    public long sysreg_read(int op0, int op1, int crn, int crm, int op2) throws BackendException {
        checkSysRegApi();
        try {
            return unicorn.cp_reg_read(op0, op1, crn, crm, op2);
        } catch (UnicornException e) {
            throw new BackendException(e);
        }
    }

    @Override
    public void sysreg_write(int op0, int op1, int crn, int crm, int op2, long value) throws BackendException {
        checkSysRegApi();
        try {
            unicorn.cp_reg_write(op0, op1, crn, crm, op2, value);
        } catch (UnicornException e) {
            throw new BackendException(e);
        }
    }

    @Override
    public void hook_add_new(final BlockHook callback, long begin, long end, Object user_data) throws BackendException {
        try {
            final Unicorn.UnHook unHook = unicorn.hook_add_new((com.github.unidbg.arm.backend.unicorn.BlockHook) (u, address, size, user) ->
                    callback.hookBlock(Unicorn2Backend.this, address, size, user), begin, end, user_data);
            callback.onAttach(unHook::unhook);
        } catch (UnicornException e) {
            throw new BackendException(e);
        }
    }

    @Override
    public final synchronized void emu_start(long begin, long until, long timeout, long count) throws BackendException {
        try {
            if (emuCount > 0) {
                unicorn.insn_limit(unicorn.insn_count() + emuCount);
            }
            unicorn.emu_start(begin, until, timeout, count);
        } catch (UnicornException e) {
            throw new BackendException(e);
        }
        if (emuCount > 0 && unicorn.insn_limit_hit()) {
            throw new ThreadContextSwitchException(); // as the emu count hook does: the thread dispatcher switches tasks
        }
    }

    @Override
    public void emu_stop() throws BackendException {
        try {
            unicorn.emu_stop();
        } catch (UnicornException e) {
            throw new BackendException(e);
        }
    }

    @Override
    public void destroy() throws BackendException {
        try {
            unicorn.closeAll();
        } catch (UnicornException e) {
            throw new BackendException(e);
        }
    }

    @Override
    public void context_restore(long context) {
        unicorn.context_restore(context);
    }

    @Override
    public void context_save(long context) {
        unicorn.context_save(context);
    }

    @Override
    public long context_alloc() {
        return unicorn.context_alloc();
    }

    @Override
    public void context_free(long context) {
        Unicorn.free(context);
    }

    @Override
    public long getMemAllocatedSize() {
        return unicorn.getMemAllocatedSize();
    }

    @Override
    public long getMemResidentSize() {
        return unicorn.getMemResidentSize();
    }

    private Unicorn.UnHook unHook;

    /**
     * The emu count of {@link #registerEmuCountHook} on an engine that counts instructions: each emu_start stops at the
     * block where the count is reached, instead of a hook on every instruction.
     */
    private long emuCount;

    @Override
    public void registerEmuCountHook(long emu_count) {
        if (unHook != null || emuCount != 0) {
            throw new IllegalStateException();
        }
        if (emu_count <= 0) {
            throw new IllegalArgumentException();
        } else if (insnCount) {
            emuCount = emu_count;
        } else {
            unHook = unicorn.registerEmuCountHook(emu_count);
        }
    }
}
