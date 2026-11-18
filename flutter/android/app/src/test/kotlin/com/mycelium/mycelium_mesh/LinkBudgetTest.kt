package com.mycelium.mycelium_mesh

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.Closeable
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger

/**
 * The accounting behind `MAX_NATIVE_LINKS` (ROADMAP T-56).
 *
 * These are the invariants the bridge's socket bound rests on. The bridge's
 * own call sites are not exercised here — they need `WifiP2pManager`, `Log`
 * and real sockets — so what each of them does with a token is a matter of
 * reading `WifiDirectService`, not of these tests.
 */
class LinkBudgetTest {
    /** A slot's socket, where the test does not care what happens to it. */
    private fun noSocket() = Closeable {}

    /** A socket that records whether the budget closed it. */
    private class Counted : Closeable {
        var closed = false
            private set

        override fun close() {
            closed = true
        }
    }

    @Test
    fun `slots are handed out up to the capacity and no further`() {
        val budget = LinkBudget(3)
        val tokens = (1..3).map { budget.take(budget.currentGeneration(), noSocket()) }
        tokens.forEach { assertNotNull(it) }
        assertEquals(3, budget.held())
        assertNull("a fourth slot was handed out", budget.take(budget.currentGeneration(), noSocket()))
        assertEquals(3, budget.held())
    }

    @Test
    fun `a refused take holds nothing`() {
        val budget = LinkBudget(1)
        budget.take(budget.currentGeneration(), noSocket())
        assertNull(budget.take(budget.currentGeneration(), noSocket()))
        // The old counter incremented first and rolled back after; a take
        // that fails must leave the count exactly where it was, or the
        // rollback becomes the thing that has to be right.
        assertEquals(1, budget.held())
    }

    @Test
    fun `releasing a slot lets exactly one more in`() {
        val budget = LinkBudget(2)
        val first = budget.take(budget.currentGeneration(), noSocket())!!
        budget.take(budget.currentGeneration(), noSocket())!!
        assertNull(budget.take(budget.currentGeneration(), noSocket()))
        budget.release(first)
        assertEquals(1, budget.held())
        assertNotNull(budget.take(budget.currentGeneration(), noSocket()))
        assertNull(budget.take(budget.currentGeneration(), noSocket()))
    }

    @Test
    fun `releasing the same token twice frees one slot`() {
        val budget = LinkBudget(2)
        val token = budget.take(budget.currentGeneration(), noSocket())!!
        budget.take(budget.currentGeneration(), noSocket())!!
        budget.release(token)
        budget.release(token)
        assertEquals("a second release freed a slot that was still held", 1, budget.held())
    }

    @Test
    fun `releasing a token this budget never issued does nothing`() {
        val budget = LinkBudget(2)
        budget.take(budget.currentGeneration(), noSocket())!!
        budget.release(9999L)
        assertEquals(1, budget.held())
    }

    @Test
    fun `a token taken before clear is inert afterwards`() {
        // The stop-and-restart case: `stop()` drops every slot while the
        // reader threads are still unwinding, and each of those readers then
        // releases the token it holds. Those releases must not touch the
        // slots the restarted service is keeping — the counter this replaced
        // went negative here, and a restarted service admitted more than its
        // capacity.
        val budget = LinkBudget(2)
        val beforeStop = budget.take(budget.currentGeneration(), noSocket())!!
        budget.take(budget.currentGeneration(), noSocket())!!
        budget.clear()
        assertEquals(0, budget.held())

        val afterRestart = budget.take(budget.currentGeneration(), noSocket())!!
        budget.take(budget.currentGeneration(), noSocket())!!
        budget.release(beforeStop)
        assertEquals("a reader from the stopped service freed a live slot", 2, budget.held())
        assertNull("the capacity was exceeded after a restart", budget.take(budget.currentGeneration(), noSocket()))

        budget.release(afterRestart)
        assertEquals(1, budget.held())
    }

    @Test
    fun `a slot is held until it is released`() {
        val budget = LinkBudget(2)
        val token = budget.take(budget.currentGeneration(), noSocket())!!
        assertTrue(budget.holds(token))
        budget.release(token)
        assertFalse(budget.holds(token))
    }

    @Test
    fun `a slot taken before clear is not held after it`() {
        // What a handler scheduled before a `stop()` asks before it commits
        // to its socket. It must get the same answer whether or not the
        // service has been started again since, which it does because a
        // token is never reissued.
        val budget = LinkBudget(2)
        val beforeStop = budget.take(budget.currentGeneration(), noSocket())!!
        budget.clear()
        assertFalse(budget.holds(beforeStop))

        val afterRestart = budget.take(budget.currentGeneration(), noSocket())!!
        assertFalse("a dropped slot came back after a restart", budget.holds(beforeStop))
        assertTrue(budget.holds(afterRestart))
    }

    @Test
    fun `a slot this budget never issued is not held`() {
        val budget = LinkBudget(1)
        assertFalse(budget.holds(7L))
    }

    @Test
    fun `clear drops every slot`() {
        val budget = LinkBudget(2)
        budget.take(budget.currentGeneration(), noSocket())
        budget.take(budget.currentGeneration(), noSocket())
        budget.clear()
        assertEquals(0, budget.held())
        assertNotNull(budget.take(budget.currentGeneration(), noSocket()))
        assertNotNull(budget.take(budget.currentGeneration(), noSocket()))
    }

    @Test
    fun `tokens are never reused`() {
        val budget = LinkBudget(1)
        val seen = HashSet<Long>()
        repeat(100) {
            val token = budget.take(budget.currentGeneration(), noSocket())!!
            assertTrue("token $token was handed out twice", seen.add(token))
            budget.release(token)
        }
    }

    @Test
    fun `clear closes the sockets the dropped slots counted`() {
        // What a handler that has not run yet cannot be relied on to do: the
        // socket was accepted and counted, and the service is stopping.
        val budget = LinkBudget(2)
        val pending = Counted()
        budget.take(budget.currentGeneration(), pending)
        assertFalse(pending.closed)
        budget.clear()
        assertTrue("a dropped slot left its socket open", pending.closed)
    }

    @Test
    fun `a released slot's socket is left alone`() {
        // The reader owns closing its own socket; the budget must not close
        // one out from under it.
        val budget = LinkBudget(2)
        val live = Counted()
        val token = budget.take(budget.currentGeneration(), live)!!
        budget.release(token)
        budget.clear()
        assertFalse("the budget closed a socket it had given back", live.closed)
    }

    @Test
    fun `a slot cannot be taken for a generation that has ended`() {
        // The accept or dial that was already under way when the service
        // stopped: its socket belongs to a service that is gone, and no
        // check made after the fact could tell, because by then the restarted
        // service is running again and has slots free.
        val budget = LinkBudget(2)
        val beforeStop = budget.currentGeneration()
        budget.clear()
        assertNull(
            "a socket from before the stop was admitted",
            budget.take(beforeStop, noSocket())
        )
        assertEquals(0, budget.held())
        assertNotNull(budget.take(budget.currentGeneration(), noSocket()))
    }

    @Test
    fun `a stale generation is refused and its socket is not closed by the budget`() {
        val budget = LinkBudget(2)
        val stale = budget.currentGeneration()
        budget.clear()
        val socket = Counted()
        assertNull(budget.take(stale, socket))
        // Nothing was taken, so the caller still owns it — as the two call
        // sites' own `close` on a null slot assumes.
        assertFalse(socket.closed)
    }

    @Test
    fun `concurrent takes never exceed the capacity`() {
        val capacity = 4
        val budget = LinkBudget(capacity)
        val live = AtomicInteger(0)
        val highWater = AtomicInteger(0)
        val threads = 8
        val start = CountDownLatch(1)
        val pool = Executors.newFixedThreadPool(threads)
        try {
            val done = CountDownLatch(threads)
            repeat(threads) {
                pool.execute {
                    start.await()
                    repeat(500) {
                        val token = budget.take(budget.currentGeneration(), noSocket())
                        if (token != null) {
                            val now = live.incrementAndGet()
                            highWater.accumulateAndGet(now) { a, b -> maxOf(a, b) }
                            live.decrementAndGet()
                            budget.release(token)
                        }
                    }
                    done.countDown()
                }
            }
            start.countDown()
            assertTrue("the workers did not finish", done.await(30, TimeUnit.SECONDS))
        } finally {
            pool.shutdownNow()
        }
        assertTrue(
            "${highWater.get()} slots were live at once, capacity is $capacity",
            highWater.get() <= capacity
        )
        assertEquals("slots were left behind", 0, budget.held())
    }
}
