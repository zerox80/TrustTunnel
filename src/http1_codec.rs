use std::io;
use std::io::ErrorKind;
use std::str::FromStr;
use std::sync::Arc;
use async_trait::async_trait;
use bytes::{BufMut, Bytes, BytesMut};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio_rustls::server::TlsStream;
use crate::{datagram_pipe, http_codec, log_id, log_utils, pipe, utils};
use crate::http_codec::{RequestHeaders, ResponseHeaders};
use crate::settings::Settings;


const MAX_RAW_HEADERS_SIZE: usize = 1024;
const MAX_HEADERS_NUM: usize = 32;
const TRAFFIC_READ_CHUNK_SIZE: usize = 16 * 1024;


pub(crate) struct Http1Codec {
    state: State,
    transport_stream: TlsStream<TcpStream>,
    /// Receives messages from [`StreamSink.download_tx`]
    download_rx: mpsc::Receiver<Option<Bytes>>,
    /// See [`StreamSink.download_tx`]
    download_tx: Option<mpsc::Sender<Option<Bytes>>>,
    /// See [`StreamSource.upload_rx`]
    upload_rx: Option<mpsc::Receiver<Option<Bytes>>>,
    /// Sends messages to [`StreamSource.upload_rx`]
    upload_tx: mpsc::Sender<Option<Bytes>>,
    parent_id_chain: log_utils::IdChain<u64>,
    next_request_id: std::ops::RangeFrom<u64>,
}

enum State {
    WaitingRequest(WaitingRequest),
    RequestInProgress(RequestInProgress),
}

struct WaitingRequest {
    buffer: BytesMut,
}

struct RequestInProgress {
    buffer: BytesMut,
}

struct Stream {
    source: StreamSource,
    sink: StreamSink,
}

struct StreamSource {
    request: RequestHeaders,
    /// Receives messages from [`Http1Codec.upload_tx`]
    upload_rx: mpsc::Receiver<Option<Bytes>>,
    id: log_utils::IdChain<u64>,
}

struct StreamSink {
    /// Sends messages to [`Http1Codec.download_rx`]
    download_tx: mpsc::Sender<Option<Bytes>>,
    id: log_utils::IdChain<u64>,
}

enum RequestStatus {
    Partial,
    Complete(Box<dyn http_codec::Stream>),
    NeedRespond(ResponseHeaders),
}


impl Http1Codec {
    pub fn new(
        _core_settings: Arc<Settings>,
        transport_stream: TlsStream<TcpStream>,
        parent_id_chain: log_utils::IdChain<u64>,
    ) -> Self {
        let (download_tx, download_rx) = mpsc::channel(1);
        let (upload_tx, upload_rx) = mpsc::channel(1);

        Self {
            state: State::WaitingRequest(WaitingRequest {
                buffer: BytesMut::with_capacity(MAX_RAW_HEADERS_SIZE),
            }),
            transport_stream,
            download_rx,
            download_tx: Some(download_tx),
            upload_rx: Some(upload_rx),
            upload_tx,
            parent_id_chain,
            next_request_id: 0..,
        }
    }

    fn on_request_headers_chunk(&mut self, buffer: BytesMut) -> io::Result<RequestStatus> {
        let mut headers = [httparse::EMPTY_HEADER; MAX_HEADERS_NUM];
        let mut request = httparse::Request::new(&mut headers);
        match request.parse(&buffer) {
            Ok(httparse::Status::Complete(_)) => {
                let mut request_builder = http::request::Request::builder()
                    .version(httparse_to_http_version(request.version.unwrap()))
                    .method(request.method.unwrap());

                let mut uri = match request.path {
                    None => return Err(io::Error::new(
                        ErrorKind::Other, format!("Invalid path: {:?}", request.path)
                    )),
                    Some(p) => match http::uri::Uri::from_str(p) {
                        Ok(uri) => uri,
                        Err(e) => return Err(io::Error::new(
                            ErrorKind::Other,
                            format!("Invalid path: path={:?}, error={}", request.path, e)
                        )),
                    }
                };

                for h in request.headers {
                     match h.name.to_ascii_lowercase().as_str() {
                        "host" if uri.authority().is_none() =>
                            uri = http::uri::Uri::builder()
                                .scheme("https")
                                .authority(h.value)
                                .path_and_query(request.path.unwrap())
                                .build()
                                .map_err(|e| io::Error::new(
                                    ErrorKind::Other,
                                    format!("Unexpected URI: error={}, authority=0x{}", e, utils::hex_dump(h.value))
                                ))?,
                        "expect" => {
                            return Ok(RequestStatus::NeedRespond(http::response::Builder::new()
                                .version(httparse_to_http_version(request.version.unwrap()))
                                .status(http::StatusCode::EXPECTATION_FAILED)
                                .body(())
                                .map_err(|e| io::Error::new(
                                    ErrorKind::Other,
                                    format!("Failed to build \"Expectation Failed\" response: {}", e)
                                ))?
                                .into_parts().0
                            ));
                        }
                        _ => request_builder = request_builder.header(h.name, h.value),
                    }
                }

                request_builder = request_builder.uri(uri);

                let _ = std::mem::replace(&mut self.state, State::RequestInProgress(RequestInProgress {
                    buffer: BytesMut::with_capacity(TRAFFIC_READ_CHUNK_SIZE),
                }));

                let id = self.parent_id_chain.extended(log_utils::IdItem::new(
                    log_utils::CONNECTION_ID_FMT, self.next_request_id.next().unwrap()
                ));
                let request = request_builder.body(())
                    .map_err(|e| io::Error::new(ErrorKind::Other, format!("Invalid request: {}", e)))?;
                Ok(RequestStatus::Complete(Box::new(Stream {
                    source: StreamSource {
                        request: request.into_parts().0,
                        upload_rx: self.upload_rx.take().unwrap(),
                        id: id.clone(),
                    },
                    sink: StreamSink {
                        download_tx: self.download_tx.take().unwrap(),
                        id,
                    }
                })))
            }
            Ok(httparse::Status::Partial) if buffer.len() < MAX_RAW_HEADERS_SIZE => {
                match &mut self.state {
                    State::WaitingRequest(x) => x.buffer = buffer,
                    _ => unreachable!(),
                }
                Ok(RequestStatus::Partial)
            },
            Ok(httparse::Status::Partial) => Err(io::Error::new(
                ErrorKind::Other, "Too long HTTP request headers"
            )),
            Err(e) => Err(io::Error::new(ErrorKind::Other, e.to_string())),
        }
    }
}

#[async_trait]
impl http_codec::HttpCodec for Http1Codec {
    async fn listen(&mut self) -> io::Result<Option<Box<dyn http_codec::Stream>>> {
        enum FiredEvent {
            Read(BytesMut),
            Stream(Option<Bytes>),
        }

        loop {
            let event = {
                let mut buffer = self.state.take_buffer();
                let wait_read = async {
                    if matches!(self.state, State::RequestInProgress(_)) {
                        let _ = self.upload_tx.reserve().await;
                    }
                    self.transport_stream.read_buf(&mut buffer).await?;
                    Ok(buffer)
                };
                tokio::pin!(wait_read);

                let wait_stream_event = self.download_rx.recv();
                tokio::pin!(wait_stream_event);

                tokio::select! {
                    r = wait_read => match r {
                        Ok(bytes) => FiredEvent::Read(bytes),
                        Err(e) => return Err(e),
                    },
                    r = wait_stream_event => match r {
                        None => return Err(io::Error::from(ErrorKind::UnexpectedEof)),
                        Some(bytes) => FiredEvent::Stream(bytes),
                    },
                }
            };

            match event {
                FiredEvent::Read(bytes) => match &mut self.state {
                    State::WaitingRequest(_) => if bytes.is_empty() {
                        return Ok(None);
                    } else {
                        match self.on_request_headers_chunk(bytes)? {
                            RequestStatus::Partial => (),
                            RequestStatus::Complete(stream) => return Ok(Some(stream)),
                            RequestStatus::NeedRespond(response) => {
                                log_id!(debug, self.parent_id_chain, "Tunnel rejected, responding with: {:?}", response);
                                let mut response = serialize_response(response);
                                self.transport_stream.write_all_buf(&mut response).await?;
                                return Ok(None);
                            }
                        }
                    }
                    State::RequestInProgress(x) => {
                        x.buffer = BytesMut::with_capacity(TRAFFIC_READ_CHUNK_SIZE);
                        match self.upload_tx.send((!bytes.is_empty()).then(|| bytes.freeze())).await {
                            Ok(_) => (),
                            Err(_) => return Err(io::Error::from(ErrorKind::UnexpectedEof)),
                        }
                    }
                }
                FiredEvent::Stream(Some(mut bytes)) => {
                    self.transport_stream.write_all_buf(&mut bytes).await?;
                }
                FiredEvent::Stream(None) => {
                    self.transport_stream.shutdown().await?;
                    return Ok(None);
                }
            }
        }
    }
}

impl http_codec::Stream for Stream {
    fn id(&self) -> log_utils::IdChain<u64> {
        self.source.id.clone()
    }

    fn request(&self) -> &dyn http_codec::PendingRequest {
        &self.source
    }

    fn split(self: Box<Self>) -> (Box<dyn http_codec::PendingRequest>, Box<dyn http_codec::PendingRespond>) {
        (Box::new(self.source), Box::new(self.sink))
    }
}

impl http_codec::PendingRequest for StreamSource {
    fn id(&self) -> log_utils::IdChain<u64> {
        self.id.clone()
    }

    fn request(&self) -> &RequestHeaders {
        &self.request
    }

    fn finalize(self: Box<Self>) -> Box<dyn pipe::Source> {
        self
    }
}

impl http_codec::PendingRespond for StreamSink {
    fn id(&self) -> log_utils::IdChain<u64> {
        self.id.clone()
    }

    fn send_response(self: Box<Self>, response: ResponseHeaders, eof: bool)
        -> io::Result<Box<dyn http_codec::RespondedStreamSink>>
    {
        log_id!(debug, self.id, "Sending response: {:?} (eof={})", response, eof);

        if let Err(e) = self.download_tx.try_send(Some(serialize_response(response))) {
            return Err(io::Error::new(
                ErrorKind::Other, format!("Failed to put response in queue: {}", e)
            ));
        }

        Ok(self)
    }
}

impl State {
    fn take_buffer(&mut self) -> BytesMut {
        match self {
            State::WaitingRequest(x) => std::mem::take(&mut x.buffer),
            State::RequestInProgress(x) => std::mem::take(&mut x.buffer),
        }
    }
}

#[async_trait]
impl pipe::Source for StreamSource {
    fn id(&self) -> log_utils::IdChain<u64> {
        self.id.clone()
    }

    async fn read(&mut self) -> io::Result<pipe::Data> {
        match self.upload_rx.recv().await.flatten() {
            None => Ok(pipe::Data::Eof),
            Some(bytes) => Ok(pipe::Data::Chunk(bytes)),
        }
    }

    fn consume(&mut self, _size: usize) -> io::Result<()> {
        // do nothing
        Ok(())
    }
}

impl http_codec::RespondedStreamSink for StreamSink {
    fn into_pipe_sink(self: Box<Self>) -> Box<dyn pipe::Sink> {
        self
    }

    fn into_datagram_sink(self: Box<Self>) -> Box<dyn http_codec::DroppingSink> {
        self
    }
}

#[async_trait]
impl pipe::Sink for StreamSink {
    fn id(&self) -> log_utils::IdChain<u64> {
        self.id.clone()
    }

    fn write(&mut self, data: Bytes) -> io::Result<Bytes> {
        match self.download_tx.try_send(Some(data)) {
            Ok(_) => Ok(Bytes::new()),
            Err(mpsc::error::TrySendError::Full(unsent)) => Ok(unsent.unwrap()),
            Err(mpsc::error::TrySendError::Closed(_)) => Err(io::Error::from(ErrorKind::UnexpectedEof)),
        }
    }

    fn eof(&mut self) -> io::Result<()> {
        self.download_tx.blocking_send(None)
            .map_err(|e| io::Error::new(ErrorKind::Other, e.to_string()))
    }

    async fn wait_writable(&mut self) -> io::Result<()> {
        match self.download_tx.reserve().await {
            Ok(_) => Ok(()),
            Err(_) => Err(io::Error::from(ErrorKind::UnexpectedEof)),
        }
    }
}

impl http_codec::DroppingSink for StreamSink {
    fn write(&mut self, data: Bytes) -> io::Result<datagram_pipe::SendStatus> {
        match self.download_tx.try_send(Some(data)) {
            Ok(_) => Ok(datagram_pipe::SendStatus::Sent),
            Err(mpsc::error::TrySendError::Full(_)) => Ok(datagram_pipe::SendStatus::Dropped),
            Err(mpsc::error::TrySendError::Closed(_)) => Err(io::Error::from(ErrorKind::UnexpectedEof)),
        }
    }
}

fn version_minor_digit(v: http::Version) -> u32 {
    match v {
        http::Version::HTTP_10 => 0,
        http::Version::HTTP_11 => 1,
        _ => unreachable!(),
    }
}

fn httparse_to_http_version(v: u8) -> http::Version {
    match v {
        0 => http::Version::HTTP_10,
        1 => http::Version::HTTP_11,
        _ => unreachable!(),
    }
}

fn serialize_response(response: ResponseHeaders) -> Bytes {
    let mut serialized = BytesMut::new();

    serialized.put(
        format!(
            "HTTP/1.{} {} {}\r\n",
            version_minor_digit(response.version),
            response.status.as_str(),
            response.status.canonical_reason().unwrap(),
        ).as_bytes()
    );

    for (name, value) in &response.headers {
        serialized.put(format!("{}: ", name).as_bytes());
        serialized.put(value.as_bytes());
        serialized.put("\r\n".as_bytes());
    }
    serialized.put("Connection: close\r\n".as_bytes());
    serialized.put("\r\n".as_bytes());

    serialized.freeze()
}
