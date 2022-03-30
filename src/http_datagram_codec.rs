use bytes::Bytes;


pub(crate) enum DecodeResult<D> {
    /// A datagram is not fully received, waiting for the next data chunk
    WantMore,
    /// A datagram is completed, the second parameter is an unprocessed chunk tail
    Complete(D, Bytes),
}

pub(crate) trait Decoder: Send {
    type Datagram;

    /// Decode a datagram chunk.
    fn decode_chunk(&mut self, data: Bytes) -> DecodeResult<Self::Datagram>;
}

pub(crate) trait Encoder: Send {
    type Datagram;

    /// Encode a datagram packet.
    ///
    /// # Return
    ///
    /// [`None`] in case encoding failed for some reason
    fn encode_packet(&self, info: &Self::Datagram) -> Option<Bytes>;
}
