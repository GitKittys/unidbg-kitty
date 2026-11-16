package com.github.unidbg.arm.backend;

import com.github.unidbg.Emulator;

import org.scijava.nativelib.NativeLibraryUtil;
import org.scijava.nativelib.NativeLoader;

public class Unicorn2Factory extends BackendFactory {

    static {
        NativeLibraryUtil.loadNativeLibrary(NativeLoader.getJniExtractor(), "unicorn");
    }

    private boolean pointerAuthentication = true;
    private boolean memoryFaultSignals;

    public Unicorn2Factory(boolean fallbackUnicorn) {
        super(fallbackUnicorn);
    }

    /**
     * arm64: whether the core authenticates pointers (FEAT_PAuth, with keys set up as the kernel does for a process);
     * on by default. Off, software sees a device without pointer authentication: the ID registers and AT_HWCAP report
     * none and the PAC instructions compilers emit (paciasp/autiasp and the other HINT-space forms) do nothing. The
     * other PAC encodings also execute as no-ops, where a core without FEAT_PAuth would make them UNDEFINED.
     */
    public Unicorn2Factory setPointerAuthentication(boolean pointerAuthentication) {
        this.pointerAuthentication = pointerAuthentication;
        return this;
    }

    /**
     * arm64: whether an invalid memory access (unmapped, or denied by the page permissions) is delivered to the guest
     * as SIGSEGV when it has a handler for it, as on a device: probes with sigsetjmp, PROT_NONE traps, code that
     * repairs a mapping and retries. Off by default: the access stays an emulation error that shows where the
     * environment is incomplete, as unidbg always reports it.
     */
    public Unicorn2Factory setMemoryFaultSignals(boolean memoryFaultSignals) {
        this.memoryFaultSignals = memoryFaultSignals;
        return this;
    }

    @Override
    protected Backend newBackendInternal(Emulator<?> emulator, boolean is64Bit) {
        return new Unicorn2Backend(emulator, is64Bit, pointerAuthentication, memoryFaultSignals);
    }

}
