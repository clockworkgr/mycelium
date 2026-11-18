package com.mycelium.mycelium_mesh

import java.io.Closeable

/**
 * How many native sockets a transport bridge holds at once, and which ones.
 *
 * A slot is taken when a socket is accepted or dialled, before anything has
 * decided whether to keep it: a handler is scheduled asynchronously, so a
 * burst of connections would otherwise see an empty link table and get a
 * reader thread each before anything refused them.
 *
 * A slot is a **token**, not a number, and the count is the number of tokens
 * outstanding. That is what keeps it from drifting:
 *
 * - releasing the same token twice frees one slot, not two;
 * - releasing a token this budget never issued does nothing;
 * - a token issued before [clear] is inert afterwards, so a reader thread
 *   still unwinding from a stopped service cannot spend a slot the restarted
 *   one is holding, and the count can never go below zero.
 *
 * Each slot also holds the socket it counts, so [clear] closes what it drops
 * rather than leaving it to a handler that has not run yet, and carries the
 * **generation** it was taken in, so a socket that arrived before a stop
 * cannot be admitted after one. Those are two different questions — is this
 * slot still counted, and did this service accept this socket — and a slot
 * answers both.
 *
 * The count this replaced was an `AtomicInteger` incremented at the accept
 * and decremented in the reader's `finally`, which leaked in both directions
 * (ROADMAP T-56): a path that returned before that `finally` exhausted the
 * bound for the life of the service, and `stop()` zeroing the counter under
 * live readers drove it negative, so a restarted service admitted more than
 * its capacity.
 *
 * Every method is safe to call from any thread.
 */
internal class LinkBudget(private val capacity: Int) {
    private val lock = Any()

    /** The next token. Never reused, so a released token stays spent. */
    private var next = 0L

    /** Bumped by [clear]; a slot may only be taken in the current one. */
    private var currentGeneration = 0

    private val outstanding = HashMap<Long, Closeable>()

    /**
     * The generation a slot taken now would belong to.
     *
     * Read *before* the blocking accept or dial whose socket the slot will
     * count, and handed to [take] afterwards: that is what makes a socket
     * which arrived before a stop unable to be admitted after one, which no
     * check made after the fact can tell.
     */
    fun currentGeneration(): Int = synchronized(lock) { currentGeneration }

    /**
     * Take a slot for [socket].
     *
     * @param generation the value [currentGeneration] gave before the socket
     *   was accepted or dialled.
     * @return the token to hand back to [release], or `null` if the service
     *   has been stopped since — in which case the socket belongs to a
     *   service that is gone — or if [capacity] slots are already
     *   outstanding. Nothing is taken either way, and the caller owns closing
     *   the socket.
     */
    fun take(generation: Int, socket: Closeable): Long? = synchronized(lock) {
        if (generation != currentGeneration || outstanding.size >= capacity) {
            null
        } else {
            val token = next++
            outstanding[token] = socket
            token
        }
    }

    /**
     * Whether [token] is still one of the outstanding slots.
     *
     * False once it has been released or dropped by [clear], and never true
     * again, because tokens are not reused. A handler that was scheduled
     * before a stop asks this before it commits to the socket: a token that
     * did not survive is a socket nothing counts any more, whether or not
     * the service has since been restarted.
     */
    fun holds(token: Long): Boolean = synchronized(lock) { outstanding.containsKey(token) }

    /**
     * Give a slot back, without closing the socket — whoever is unwinding
     * owns that. A token that is not outstanding is ignored.
     */
    fun release(token: Long) {
        synchronized(lock) { outstanding.remove(token) }
    }

    /**
     * Drop every slot, close the sockets they counted, and start a new
     * generation.
     *
     * The closing is what a handler that has not run yet cannot be relied on
     * to do, and the new generation is what stops a socket already accepted
     * from being admitted into the next service. Readers that have not
     * finished unwinding still hold their tokens and will release them; those
     * releases are no-ops.
     */
    fun clear() {
        // Closed outside the lock: a close can block, and nothing else may
        // wait on this lock while it does.
        val dropped = synchronized(lock) {
            currentGeneration++
            val sockets = outstanding.values.toList()
            outstanding.clear()
            sockets
        }
        for (socket in dropped) {
            try {
                socket.close()
            } catch (_: Exception) {
            }
        }
    }

    /** How many slots are outstanding. */
    fun held(): Int = synchronized(lock) { outstanding.size }
}
