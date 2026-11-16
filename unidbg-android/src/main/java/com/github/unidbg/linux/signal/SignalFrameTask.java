package com.github.unidbg.linux.signal;

import com.github.unidbg.AbstractEmulator;
import com.github.unidbg.Emulator;
import com.github.unidbg.signal.AbstractSignalTask;
import com.github.unidbg.signal.SignalOps;
import com.github.unidbg.thread.AbstractWaiter;

/**
 * A signal queued on the {@link com.github.unidbg.thread.Task} that receives it ({@link
 * com.github.unidbg.thread.Task#addSignalTask}), to be delivered the way the arm64 kernel does it: when that thread
 * next enters user mode, with a rt_sigframe pushed on its own stack and the thread continuing in the handler. The
 * delivery is done by the syscall handler's {@link com.github.unidbg.signal.SignalDeliverer} at that point (after an
 * interrupted syscall's result is in place), not by the thread dispatcher as a separate task: the task is never
 * dispatchable on its own.
 */
public class SignalFrameTask extends AbstractSignalTask {

    private static final AbstractWaiter DELIVERED_ON_RETURN = new AbstractWaiter() {
        @Override
        public boolean canDispatch() {
            return false;
        }

        @Override
        public void onContinueRun(Emulator<?> emulator) {
        }
    };

    private final SigInfo info;

    public SignalFrameTask(Emulator<?> emulator, SigInfo info) {
        super(info.signo);
        this.info = info;
        setWaiter(emulator, DELIVERED_ON_RETURN);
    }

    public SigInfo getInfo() {
        return info;
    }

    @Override
    public Number callHandler(SignalOps signalOps, AbstractEmulator<?> emulator) {
        throw new IllegalStateException(this + " is delivered when the thread enters user mode, not dispatched");
    }

    @Override
    public String toThreadString() {
        return "SignalFrameTask " + info;
    }

}
