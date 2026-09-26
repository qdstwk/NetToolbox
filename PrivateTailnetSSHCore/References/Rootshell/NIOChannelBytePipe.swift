//
//  NIOChannelBytePipe.swift
//  rootshell
//
//  AsyncBytePipe adapter over an arbitrary NIO Channel. Bridges the
//  push-based NIO pipeline (where bytes arrive via channelRead) with
//  the pull-based ``AsyncBytePipe`` API. The caller supplies whatever
//  unwrapping handlers its channel type needs; this pipe only requires
//  that plain ByteBuffers reach the end of the inbound pipeline.
//
//  Copyright (c) 2026 Kit Knox / Rootshell LLC
//

import Foundation
import NIOCore
import NIOFoundationCompat
import os

nonisolated enum NIOChannelBytePipeError: Error {
    /// The peer closed the channel before a `readExactly` request was
    /// fully satisfied.
    case unexpectedEndOfStream
}

/// AsyncBytePipe wrapping a NIO Channel. Inbound bytes are buffered in
/// an actor-protected queue with a single waiter slot (consumers read
/// sequentially, so multi-waiter support would be wasted complexity).
/// Writes go straight through `channel.writeAndFlush`.
actor NIOChannelBytePipe: AsyncBytePipe {

    private nonisolated static let logger = Logger(
        subsystem: "com.kk2.rootshell",
        category: "NIOChannelBytePipe"
    )

    private nonisolated let channel: Channel

    /// Inbound queue. NIO's channelRead handler calls ``enqueue`` from
    /// the event loop; the consumer calls ``read`` from its own actor.
    /// Pending bytes accumulate here until a reader claims them.
    private var inboundBuffer: [Data] = []

    /// Single-waiter slot. Consumers only ever have one read
    /// outstanding, so we don't need a deque of continuations — a
    /// fatal trap if two concurrent reads landed would catch any
    /// refactor that broke that invariant.
    private var pendingReader: CheckedContinuation<Data?, Never>?

    /// Set true when the peer closed the channel. Once true, all
    /// further reads return nil (clean EOF) immediately.
    private var closed: Bool = false

    /// Holdover for partial reads — `AsyncBytePipe.read(maxBytes:)`
    /// can return less than a full inbound chunk if the caller asked
    /// for less. The remainder of the chunk stays here.
    private var pendingTail: Data = Data()

    /// Install the pipe + its supporting handlers on the given channel.
    /// Must be called on the channel's event loop. `extraHandlers` are
    /// added (in order) ahead of the pipe's own inbound handler — the
    /// hook for channel-type-specific unwrapping. Citadel DirectTCPIP
    /// channels already carry ByteBuffers and need no extra handler here.
    nonisolated static func install(
        on channel: Channel,
        extraHandlers: [ChannelHandler] = []
    ) throws -> NIOChannelBytePipe {
        let pipe = NIOChannelBytePipe(channel: channel)
        let handler = InboundHandler(pipe: pipe)
        for extra in extraHandlers {
            try channel.pipeline.syncOperations.addHandler(extra)
        }
        try channel.pipeline.syncOperations.addHandler(handler)
        return pipe
    }

    // An actor's synchronous initializer is inherently nonisolated (callable
    // from `install` on the event loop); the `nonisolated` keyword is invalid
    // here, so it must be omitted.
    private init(channel: Channel) {
        self.channel = channel
    }

    // MARK: - AsyncBytePipe

    func read(maxBytes: Int) async throws -> Data? {
        if !pendingTail.isEmpty {
            return takeTail(maxBytes: maxBytes)
        }
        if let next = inboundBuffer.first {
            inboundBuffer.removeFirst()
            return clamp(next, to: maxBytes)
        }
        if closed {
            return nil
        }
        // Wait for the next inbound chunk (or close).
        let data: Data? = await withCheckedContinuation { continuation in
            pendingReader = continuation
        }
        if let data = data {
            return clamp(data, to: maxBytes)
        }
        return nil
    }

    /// Accumulate exactly `count` bytes on top of the chunked ``read``
    /// primitive. Throws ``NIOChannelBytePipeError/unexpectedEndOfStream``
    /// if the peer closes mid-message.
    func readExactly(_ count: Int) async throws -> Data {
        var out = Data()
        out.reserveCapacity(count)
        while out.count < count {
            guard let chunk = try await read(maxBytes: count - out.count), !chunk.isEmpty else {
                throw NIOChannelBytePipeError.unexpectedEndOfStream
            }
            out.append(chunk)
        }
        return out
    }

    nonisolated func write(_ data: Data) async throws {
        var buffer = channel.allocator.buffer(capacity: data.count)
        buffer.writeBytes(data)
        try await channel.writeAndFlush(buffer).get()
    }

    nonisolated func close() async {
        try? await channel.close()
    }

    // MARK: - Internal hooks for InboundHandler

    /// Called from the NIO event loop when bytes arrive. Either hands
    /// the buffer to a parked reader or queues it for the next read.
    fileprivate func enqueue(_ data: Data) {
        if let reader = pendingReader {
            pendingReader = nil
            reader.resume(returning: data)
            return
        }
        inboundBuffer.append(data)
    }

    fileprivate func finish() {
        closed = true
        if let reader = pendingReader {
            pendingReader = nil
            reader.resume(returning: nil)
        }
    }

    // MARK: - Helpers

    private func clamp(_ data: Data, to maxBytes: Int) -> Data {
        if data.count <= maxBytes {
            return data
        }
        pendingTail = data.subdata(in: maxBytes..<data.count)
        return data.prefix(maxBytes)
    }

    private func takeTail(maxBytes: Int) -> Data {
        if pendingTail.count <= maxBytes {
            let out = pendingTail
            pendingTail = Data()
            return out
        }
        let prefix = pendingTail.prefix(maxBytes)
        pendingTail = pendingTail.dropFirst(maxBytes)
        return Data(prefix)
    }
}

/// Inbound-only NIO handler that pushes received `ByteBuffer`s into
/// the parent pipe's actor-isolated queue. Hop to the actor via a
/// detached Task because NIO handler callbacks run on the event loop,
/// not the actor's executor.
private nonisolated final class InboundHandler: ChannelInboundHandler, @unchecked Sendable {
    typealias InboundIn = ByteBuffer

    private let pipe: NIOChannelBytePipe

    init(pipe: NIOChannelBytePipe) {
        self.pipe = pipe
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        var buffer = self.unwrapInboundIn(data)
        guard let bytes = buffer.readData(length: buffer.readableBytes), !bytes.isEmpty else { return }
        let pipe = self.pipe
        Task { await pipe.enqueue(bytes) }
    }

    func channelInactive(context: ChannelHandlerContext) {
        let pipe = self.pipe
        Task { await pipe.finish() }
        context.fireChannelInactive()
    }

    func errorCaught(context: ChannelHandlerContext, error: Error) {
        let pipe = self.pipe
        Task { await pipe.finish() }
        context.close(promise: nil)
    }
}
