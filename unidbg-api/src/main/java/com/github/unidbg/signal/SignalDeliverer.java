package com.github.unidbg.signal;

import com.github.unidbg.Emulator;
import com.github.unidbg.arm.backend.BackendException;

/**
 * Optionally implemented by a syscall handler that can deliver a signal to the running thread at once, the way the
 * kernel does on its way back to user mode: a backend hook (a system instruction, an undefined instruction, a syscall
 * the thread sends itself a signal with) cannot redirect the thread from inside the hook, so it stops emulation and
 * asks for a delivery check; the emulator then lets the handler set up the thread's registers (its signal frame, PC =
 * the handler) and resumes emulation in the same task, without a thread switch.
 */
public interface SignalDeliverer {

    /**
     * Delivers what is queued for the running thread, before emulation starts or resumes.
     *
     * @param pc where the running thread is about to continue
     * @return where it continues after delivery (<code>pc</code> if nothing was delivered), or -1 if a signal's
     * default action terminated the process: emulation ends
     */
    long deliverPendingSignals(Emulator<?> emulator, long pc);

    /**
     * @return true, once, if a hook asked for a delivery check and stopped emulation since the last call
     */
    boolean takeDeliveryRequest();

    /**
     * Emulation stopped with an error from the backend. If it is a memory fault the guest handles (SIGSEGV), delivers
     * it: the backend stopped at the faulting instruction.
     *
     * @param pc where emulation stopped
     * @return where the thread continues (or -1 if a default action terminated the process), or null if the error is
     * not turned into a signal and stays an emulation error
     */
    default Long deliverFault(Emulator<?> emulator, BackendException error, long pc) {
        return null;
    }

}
