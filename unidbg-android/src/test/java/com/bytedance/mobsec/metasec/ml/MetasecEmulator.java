package com.bytedance.mobsec.metasec.ml;

import com.github.unidbg.AndroidEmulator;
import com.github.unidbg.Emulator;
import com.github.unidbg.Module;
import com.github.unidbg.arm.backend.Backend;
import com.github.unidbg.arm.backend.CodeHook;
import com.github.unidbg.arm.backend.UnHook;
import com.github.unidbg.linux.android.dvm.VM;
import com.github.unidbg.memory.Memory;
import com.github.unidbg.pointer.UnidbgPointer;
import unicorn.Arm64Const;

import java.io.Closeable;
import java.io.File;

/**
 * One emulated device, set up once, with the operations the harness needs exposed:
 * <ul>
 *   <li>{@link #sign(String, String)} — the seven headers metasec produces for a request;</li>
 *   <li>{@link #ttEncrypt(byte[])} — the applog envelope ({@code libEncryptor.so});</li>
 *   <li>{@link #key()} / {@link #iv()} — the key/iv the encryptor chose for the last {@code ttEncrypt}, so the caller can
 *       decrypt its own output;</li>
 *   <li>{@link #emulator()} / {@link #vm()} — the underlying pieces, for a caller that needs more.</li>
 * </ul>
 *
 * Both native libraries live in the <b>same</b> emulator: metasec is brought up from the recording first (its own threads,
 * Keva, property area), then {@code libEncryptor.so} is loaded on top of that VM. Each instance owns its own emulator and its
 * own rootfs copy ({@code target/rootfs/metasec-<n>}), so callers who want concurrency create more instances — one emulator
 * per instance, because a second/third emulator in one JVM is where the engine falls over
 * (doc/unidbg-bugs-observed.md §4).
 */
public class MetasecEmulator implements Closeable {

    private static final File RESOURCES = Build.RESOURCES;
    /** libEncryptor hands key/iv/in/len/out to its AES routine here (doc/applog-ttencrypt.md §3) */
    private static final long AES_INPUT = 0x2a5c;
    private static final String ENCRYPTOR_UTIL = "com/bytedance/frameworks/encryptor/EncryptorUtil";

    private final MetasecSign signer;
    private final byte[] key = new byte[16], iv = new byte[16];
    /** closing twice must not touch the native side twice (doc/unidbg-bugs-observed.md §4) */
    private final java.util.concurrent.atomic.AtomicBoolean closed = new java.util.concurrent.atomic.AtomicBoolean();

    public MetasecEmulator() throws Exception {
        this(false);
    }

    /**
     * @param verbose unidbg's JNI trace
     */
    public MetasecEmulator(boolean verbose) throws Exception {
        signer = new MetasecSign();
        signer.run(verbose, false); // the recorded init flow; the reference sign it makes is harmless here
        String encryptorPath = new Build(new File(RESOURCES, "device/metasec.json")).encryptor();

        Memory memory = signer.emulator().getMemory();
        Module library = memory.dlopen(encryptorPath);
        if (library == null) {
            throw new IllegalStateException("dlopen(" + encryptorPath + ") failed");
        }
        captureKeyIv(signer.emulator(), library);
        Number onLoad = library.callFunction(signer.emulator(), "JNI_OnLoad", signer.vm().getJavaVM(), null);
        System.out.printf("  libEncryptor.so at 0x%x, JNI_OnLoad -> 0x%x%n", library.base, onLoad.intValue());
    }

    /** one of metasec's own HTTP sign calls: the "name\r\nvalue" block it produces */
    public synchronized String sign(String url, String headerBlob) {
        return signer.signRaw(url, headerBlob);
    }

    /** the WS sign entry (0x5000001 ws_callback → metasec+0x291324), as sscronet calls it for ws traffic:
     *  single argument = the service/method kv blob, no URL (sscronet+0x396074 BLR X27 with only X0=blob) */
    public synchronized String signWs(String headerBlob) {
        return signer.signWsRaw(headerBlob);
    }

    /** diagnostic: sign the same URL+blob through the http and the ws entry, to attribute a 0 to one of them */
    public synchronized String[][] signBothEntries(String url, String headerBlob) {
        return signer.signBothEntries(url, headerBlob);
    }

    /** {@code EncryptorUtil.ttEncrypt}: the key/iv are new for each call, see {@link #key()} / {@link #iv()} */
    public synchronized byte[] ttEncrypt(byte[] plaintext) {
        Object value = signer.vm().resolveClass(ENCRYPTOR_UTIL)
                .callStaticJniMethodObject(signer.emulator(), "ttEncrypt([BI)[B", plaintext, plaintext.length)
                .getValue();
        return value instanceof byte[] ? (byte[]) value : null;
    }

    /** device_register answered: metasec gets the install's did/iid (a first-launch profile defers them, {@link MetasecSign#installed}) */
    public synchronized void installed(String did, String iid) throws Exception {
        signer.installed(did, iid);
    }

    /** metasec's mssdk channel goes out for real from now on */
    public synchronized void goLive() throws java.io.IOException {
        signer.goLive();
    }

    /** while the pbbp2 WSS stay runs, park the mssdk channel (it blocks the sign-servicing thread) */
    public synchronized void holdMssdk(boolean on) {
        signer.holdMssdk(on);
    }

    /** let the app run for ms of guest time (metasec's threads run meanwhile) */
    public synchronized void pass(long ms) {
        signer.passGuest(ms);
    }

    public byte[] key() {
        return key.clone();
    }

    public byte[] iv() {
        return iv.clone();
    }

    public AndroidEmulator emulator() {
        return signer.emulator();
    }

    public VM vm() {
        return signer.vm();
    }

    /** the syscall layer of the emulator (the guest clock lives there) */
    public MetasecSyscalls syscalls() {
        return signer.syscalls();
    }

    /** the device's answers to Java calls, for another native library of the app in this emulator ({@link BadgerBridge}) */
    ProfileJni jni() {
        return signer.jni();
    }

    /** the device's file system of this run */
    File rootDir() {
        return signer.rootDir();
    }

    @Override
    public void close() {
        if (!closed.compareAndSet(false, true)) {
            return;
        }
        try {
            signer.close();
        } catch (java.io.IOException e) {
            throw new IllegalStateException(e);
        }
    }

    private void captureKeyIv(Emulator<?> emulator, final Module library) {
        emulator.getBackend().hook_add_new(new CodeHook() {
            @Override
            public void hook(Backend backend, long address, int size, Object user) {
                try {
                    long keyPointer = backend.reg_read(Arm64Const.UC_ARM64_REG_X0).longValue();
                    long ivPointer = backend.reg_read(Arm64Const.UC_ARM64_REG_X2).longValue();
                    if (keyPointer < 0x10000 || keyPointer > 0xf0000000L || ivPointer < 0x10000 || ivPointer > 0xf0000000L) {
                        return;
                    }
                    System.arraycopy(UnidbgPointer.pointer(emulator, keyPointer).getByteArray(0, 16), 0, key, 0, 16);
                    System.arraycopy(UnidbgPointer.pointer(emulator, ivPointer).getByteArray(0, 16), 0, iv, 0, 16);
                } catch (RuntimeException ignored) {
                    // not a readable key/iv at this call
                }
            }

            @Override
            public void onAttach(UnHook unHook) {
            }

            @Override
            public void detach() {
            }
        }, library.base + AES_INPUT, library.base + AES_INPUT, null);
    }

}
