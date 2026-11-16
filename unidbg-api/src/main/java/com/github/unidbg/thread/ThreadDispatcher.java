package com.github.unidbg.thread;

import com.github.unidbg.signal.SignalOps;
import com.github.unidbg.signal.SignalTask;

import java.util.List;
import java.util.concurrent.TimeUnit;

public interface ThreadDispatcher extends SignalOps {

    void addThread(ThreadTask task);

    List<Task> getTaskList();

    Number runMainForResult(MainTask main);

    void runThreads(long timeout, TimeUnit unit);

    /**
     * Runs the threads until none can run: each one waits (for a lock, a condition, a timed wait or forever). Threads
     * that serve the whole process never finish, so this is the point their work is done.
     */
    default void runThreadsUntilIdle() {
        throw new UnsupportedOperationException();
    }

    int getTaskCount();

    boolean sendSignal(int tid, int sig, SignalTask signalTask);

    RunnableTask getRunningTask();

}
